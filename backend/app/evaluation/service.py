from math import ceil
from statistics import median
from time import perf_counter
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException

from app.evaluation.models import (
    EvaluationMetrics,
    PolicyModeEvaluation,
    EvaluationRequest,
    EvaluationRunResult,
    EvaluationSummary,
    ScenarioEvaluation,
)
from app.evaluation.storage import SQLiteEvaluationStorage
from app.simulation.models import SimulationRunRequest, SimulationRunSummary
from app.simulation.service import AttackSimulationService, SCENARIOS


P95_MINIMUM_SAMPLE_SIZE = 20


class EvaluationService:
    """Run every defined scenario repeatedly and aggregate measured outputs."""

    def __init__(
        self,
        simulations: AttackSimulationService,
        storage: SQLiteEvaluationStorage,
    ) -> None:
        self._simulations = simulations
        self._storage = storage

    def get_evaluation(self, evaluation_id: str) -> EvaluationSummary:
        evaluation = self._storage.get(evaluation_id)
        if evaluation is None:
            raise HTTPException(status_code=404, detail="Evaluation not found")
        return evaluation

    def run(self, request: EvaluationRequest) -> EvaluationSummary:
        evaluation_id = request.evaluation_id or uuid4().hex[:16]
        if self._storage.get(evaluation_id) is not None:
            raise HTTPException(
                status_code=409,
                detail="Evaluation ID has already been used",
            )

        started_at = datetime.now(timezone.utc)
        started_clock = perf_counter()
        run_results: list[EvaluationRunResult] = []

        for scenario in SCENARIOS:
            for policy_mode in request.policy_modes:
                policy_key = "b" if policy_mode == "baseline" else "a"
                for repetition in range(1, request.repetitions + 1):
                    simulation_id = (
                        f"ev-{evaluation_id}-{scenario.name}-{policy_key}-{repetition}"
                    )
                    actor_id = f"eval-{simulation_id}"
                    expected_actions = self._simulations.expected_actions(
                        scenario.name,
                        request.repeated_access_count,
                    )
                    try:
                        summary = self._simulations.run(
                            SimulationRunRequest(
                                scenario=scenario.name,
                                simulation_id=simulation_id,
                                actor_id=actor_id,
                                policy_mode=policy_mode,
                                repeat_count=(
                                    request.repeated_access_count
                                    if scenario.name == "repeated_access"
                                    else 2
                                ),
                            )
                        )
                    except Exception as exc:
                        detail = getattr(exc, "detail", None)
                        run_results.append(
                            EvaluationRunResult(
                                scenario=scenario.name,
                                policy_mode=policy_mode,
                                repetition=repetition,
                                simulation_id=simulation_id,
                                actor_id=actor_id,
                                status="failed",
                                scenario_expected_actions=expected_actions,
                                expected_action_sequence_match=None,
                                simulation_summary=None,
                                execution_error=str(
                                    detail if detail is not None else exc
                                ),
                            )
                        )
                        continue

                    complete = self._is_complete(summary)
                    actions_match = (
                        summary.observed_actions == expected_actions
                        if complete
                        else None
                    )
                    run_results.append(
                        EvaluationRunResult(
                            scenario=scenario.name,
                            policy_mode=policy_mode,
                            repetition=repetition,
                            simulation_id=simulation_id,
                            actor_id=actor_id,
                            status="completed" if complete else "incomplete",
                            scenario_expected_actions=expected_actions,
                            expected_action_sequence_match=actions_match,
                            simulation_summary=summary,
                        )
                    )

        scenario_metrics = [
            self._aggregate(
                scenario.name,
                request.repetitions * len(request.policy_modes),
                [run for run in run_results if run.scenario == scenario.name],
            )
            for scenario in SCENARIOS
        ]
        overall = self._aggregate(None, len(run_results), run_results)
        policy_mode_metrics = [
            PolicyModeEvaluation(
                policy_mode=policy_mode,
                **self._aggregate(
                    None,
                    request.repetitions * len(SCENARIOS),
                    [run for run in run_results if run.policy_mode == policy_mode],
                ).model_dump(),
            )
            for policy_mode in request.policy_modes
        ]
        ended_at = datetime.now(timezone.utc)
        summary = EvaluationSummary(
            evaluation_id=evaluation_id,
            status=(
                "completed"
                if all(run.status == "completed" for run in run_results)
                else "partial"
            ),
            repetitions_per_scenario=request.repetitions,
            repeated_access_count=request.repeated_access_count,
            policy_mode_metrics=policy_mode_metrics,
            scenarios=scenario_metrics,
            overall=overall,
            runs=run_results,
            started_at=started_at,
            ended_at=ended_at,
            elapsed_seconds=round(perf_counter() - started_clock, 6),
            unavailable_measurements=[
                "duplicate_decoys_avoided: the decoy registry does not expose insert-conflict counts",
                "p95_latency_ms: reported only with at least 20 measured runs per aggregate",
                "classification accuracy, precision, recall, and F1: no classifier prediction target is evaluated by this harness",
                "event_recording_rate denominator excludes run attempts that failed before producing a simulation summary",
            ],
        )
        self._storage.save(summary)
        return summary

    @staticmethod
    def _is_complete(summary: SimulationRunSummary) -> bool:
        return (
            summary.interactions_recorded == summary.interactions_attempted
            and not summary.errors
        )

    @classmethod
    def _aggregate(
        cls,
        scenario,
        runs_requested: int,
        runs: list[EvaluationRunResult],
    ) -> ScenarioEvaluation | EvaluationMetrics:
        summaries = [
            run.simulation_summary
            for run in runs
            if run.simulation_summary is not None
        ]
        completed_runs = sum(run.status == "completed" for run in runs)
        incomplete_runs = sum(run.status == "incomplete" for run in runs)
        failed_runs = sum(run.status == "failed" for run in runs)
        attempted = sum(summary.interactions_attempted for summary in summaries)
        recorded = sum(summary.interactions_recorded for summary in summaries)
        strategy_measured = [
            summary
            for summary in summaries
            if summary.strategy_change_count is not None
        ]
        changed_runs = sum(
            summary.strategy_change_count > 0
            for summary in strategy_measured
        )
        decoy_runs = sum(summary.decoys_generated > 0 for summary in summaries)
        latency_samples = sorted(
            summary.elapsed_seconds * 1000
            for summary in summaries
        )
        error_count = sum(
            len(summary.errors)
            for summary in summaries
        ) + failed_runs
        generated_decoy_categories: dict[str, int] = {}
        bundle_asset_categories: dict[str, int] = {}
        strategy_selection_counts: dict[str, int] = {}
        for summary in summaries:
            for category, count in summary.generated_decoy_categories.items():
                generated_decoy_categories[category] = (
                    generated_decoy_categories.get(category, 0) + count
                )
            for category, count in summary.bundle_asset_categories.items():
                bundle_asset_categories[category] = (
                    bundle_asset_categories.get(category, 0) + count
                )
            selected_strategies = summary.observed_strategies or (
                [summary.final_adaptation_strategy]
                if summary.final_adaptation_strategy is not None
                else []
            )
            for strategy in selected_strategies:
                strategy_selection_counts[strategy] = (
                    strategy_selection_counts.get(strategy, 0) + 1
                )

        metrics = EvaluationMetrics(
            runs_requested=runs_requested,
            runs_with_summary=len(summaries),
            completed_runs=completed_runs,
            incomplete_runs=incomplete_runs,
            failed_runs=failed_runs,
            completion_rate=round(completed_runs / runs_requested, 6)
            if runs_requested
            else 0.0,
            interactions_attempted=attempted,
            interactions_recorded=recorded,
            event_recording_rate=(recorded / attempted) if attempted else None,
            strategy_measurement_runs=len(strategy_measured),
            strategy_changed_runs=changed_runs,
            strategy_change_rate=(
                changed_runs / len(strategy_measured)
                if strategy_measured
                else None
            ),
            decoy_generation_measurement_runs=len(summaries),
            decoy_generation_runs=decoy_runs,
            decoy_generation_rate=(
                decoy_runs / len(summaries) if summaries else None
            ),
            decoys_generated=sum(summary.decoys_generated for summary in summaries),
            generated_decoy_categories=dict(sorted(generated_decoy_categories.items())),
            strategy_selection_counts=dict(sorted(strategy_selection_counts.items())),
            errors=error_count,
            latency_sample_count=len(latency_samples),
            median_latency_ms=(
                round(median(latency_samples), 3)
                if latency_samples
                else None
            ),
            p95_latency_ms=cls._p95(latency_samples),
            p95_minimum_sample_size=P95_MINIMUM_SAMPLE_SIZE,
            bundles_generated=sum(len(summary.bundle_ids) for summary in summaries),
            validated_bundles=sum(
                result.valid
                for summary in summaries
                for result in summary.bundle_validation_results
            ),
            bundle_validation_failures=sum(
                not result.valid
                for summary in summaries
                for result in summary.bundle_validation_results
            ),
            bundle_asset_categories=dict(sorted(bundle_asset_categories.items())),
        )
        if scenario is None:
            return metrics
        return ScenarioEvaluation(scenario=scenario, **metrics.model_dump())

    @staticmethod
    def _p95(samples: list[float]) -> float | None:
        if len(samples) < P95_MINIMUM_SAMPLE_SIZE:
            return None
        nearest_rank = ceil(0.95 * len(samples))
        return round(samples[nearest_rank - 1], 3)
