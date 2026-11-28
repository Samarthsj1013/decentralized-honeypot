"""Offline paired experiment runner using inert, deterministic synthetic records."""

from __future__ import annotations

import csv
import io
from functools import lru_cache
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timezone
from statistics import median
from time import perf_counter
from uuid import uuid4

from fastapi import HTTPException

from app.events.models import HoneypotEvent
from app.experiments.models import ExperimentComparison, ExperimentRequest, ExperimentResult, MetricDifference, ModeMetrics, ScenarioResult
from app.experiments.storage import ExperimentStorage
from app.experiments.closed_loop import (
    ContextualStrategyPolicy,
    POLICY_VERSION,
    simulate_reaction,
    strategy_reward,
)
from app.incidents.service import IncidentService
from app.incidents.storage import SQLiteIncidentStorage
from app.profiling.features import extract_features
from app.profiling.models_ml import train_profile_models
from app.profiling.service import AttackerProfileService, RECOMMENDATION_POLICY
from app.simulation.adversary import SCENARIOS, SyntheticEvent, generate_scenario


METRIC_DEFINITIONS = {
    "detection_coverage": "Detector true positives divided by ground-truth suspicious synthetic events.",
    "event_capture_rate": "Events processed locally divided by generated events; no network transport is involved.",
    "incident_detection_rate": "Suspicious scenarios with at least one detector alert divided by suspicious scenarios.",
    "detection_latency_median_seconds": "Median virtual event time from scenario start to first detector alert, among detected scenarios.",
    "false_positive_rate": "Benign synthetic events flagged divided by all benign synthetic events.",
    "false_negative_rate": "Suspicious synthetic events not flagged divided by all suspicious synthetic events.",
    "scenario_completion_rate": "Completed scenario-mode repetitions divided by requested scenario-mode repetitions.",
    "adaptation_frequency": "Adaptive runs with a selected non-neutral policy divided by adaptive runs.",
    "adaptation_effectiveness": "Adaptive minus baseline detection coverage in percentage points; only when both modes are included.",
    "average_event_processing_ms": "Measured event-loop wall time divided by events processed; includes per-event local incident correlation, excludes model training, scenario generation/classification, temporary incident-store setup, and experiment-result persistence.",
    "execution_time_seconds": "Observed wall time for the experiment request; machine-dependent.",
    "peak_memory_bytes": "Unavailable: process memory is not measured by this harness.",
    "simulated_engagement_rate": "Completed synthetic runs with a simulated non-abandon reaction divided by completed runs; based on explicit seeded reaction probabilities, not observed attackers.",
    "mean_synthetic_interaction_depth": "Mean generated synthetic event count plus any simulated follow-up events per completed run; not a real session depth.",
    "median_synthetic_session_duration_seconds": "Median virtual time between the first and last generated event, including simulated follow-up timestamps; no wall-clock attacker dwell is observed.",
    "unique_decoys_accessed": "Unavailable: synthetic events do not identify actual decoy assets accessed.",
}
MODE_DEFINITIONS = {
    "baseline": "Fixed static detector thresholds and a static baseline deception strategy; paired seeded reaction rules are simulated for comparison.",
    "adaptive": "Existing synthetic profile classifier and recommendation policy select a local strategy and simulation-only detector thresholds; the same seeded reaction model measures synthetic engagement. No live configuration is changed.",
    "closed_loop": "A deterministic, experiment-local contextual strategy policy selects from a bounded synthetic library, simulates a seeded attacker reaction, measures the resulting events, and updates bounded reward estimates. No live configuration is changed.",
}


def _as_events(rows: list[SyntheticEvent]) -> list[HoneypotEvent]:
    return [HoneypotEvent(
        event_id=row.event_id, timestamp=row.occurred_at, decoy_id="synthetic-telemetry",
        actor_id="synthetic-experiment-actor", action=row.event_type,
        event_type="external_telemetry", severity=row.severity, source="external",
        source_system=row.source_system, sensor_id=row.sensor_id, source_event_id=row.event_id,
        telemetry_event_type=row.event_type, source_ip=row.source_ip,
        destination_port=row.destination_port, protocol=row.protocol, attributes=row.attributes,
    ) for row in rows]


@lru_cache(maxsize=1)
def _synthetic_model_bundle():
    return train_profile_models(samples_per_category=12, random_seed=2026)


class ExperimentService:
    def __init__(self, storage: ExperimentStorage | None = None):
        self.storage = storage or ExperimentStorage()

    def get(self, experiment_id: str) -> ExperimentResult:
        result = self.storage.get(experiment_id)
        if result is None:
            raise HTTPException(404, "Experiment not found")
        return result

    def list(self, limit: int = 50, offset: int = 0):
        return self.storage.list(limit, offset)

    def run(self, request: ExperimentRequest) -> ExperimentResult:
        experiment_id = request.experiment_id or uuid4().hex[:16]
        if self.storage.get(experiment_id) is not None:
            raise HTTPException(409, "Experiment ID has already been used")
        started = perf_counter()
        # Existing profiling features and synthetic classifier/recommendation policy
        # are reused. Training data is generated locally, never from telemetry.
        model_bundle = _synthetic_model_bundle()
        rows: list[ScenarioResult] = []
        closed_loop_policy = ContextualStrategyPolicy(request.seed)
        for scenario_index, scenario in enumerate(request.scenarios):
            for repetition in range(1, request.repetitions + 1):
                scenario_seed = (request.seed + scenario_index * 100003 + repetition * 997) % (2**32)
                generated = generate_scenario(scenario, scenario_seed)
                features = extract_features(_as_events(generated), window_seconds=86400, as_of=generated[-1].occurred_at) if generated else {}
                raw_profile_category = str(model_bundle["classifier"].predict([[float(features.get(name, 0)) for name in model_bundle["metadata"]["feature_columns"]]])[0]) if generated else "unknown"
                profile_category = AttackerProfileService._classification_with_evidence_gate(
                    raw_profile_category, features, len(generated)
                )
                policy = RECOMMENDATION_POLICY.get(profile_category, RECOMMENDATION_POLICY["unknown"])
                for mode in request.modes:
                    strategy = "static_baseline" if mode == "baseline" else policy["strategy"]
                    reason = None if mode == "baseline" else f"Local profile predicted {profile_category}; existing recommendation policy selected {strategy}. No live policy was changed."
                    mode_events = generated
                    decision = None
                    reactions: list[str] = []
                    original_event_count = len(generated)
                    if mode == "closed_loop":
                        decision = closed_loop_policy.select(profile_category)
                        strategy = decision.strategy
                        reason = decision.reason
                        followups, reactions = simulate_reaction(
                            generated, profile_category, strategy,
                            (scenario_seed + 65537) % (2**32),
                        )
                        mode_events = [*generated, *followups]
                    else:
                        # Use the same random seed for paired modes so differences
                        # arise from the explicit strategy reaction probability,
                        # not an unrelated random draw.
                        followups, reactions = simulate_reaction(
                            generated, profile_category, strategy,
                            (scenario_seed + 65537) % (2**32),
                        )
                    thresholds = {"auth": 3, "ports": 5, "commands": 3, "protocols": 3, "sensors": 2}
                    if mode in {"adaptive", "closed_loop"}:
                        if profile_category == "authentication_probing": thresholds["auth"] = 2
                        if profile_category in {"reconnaissance", "repeated_connection"}: thresholds["ports"] = 3
                        if profile_category == "suspicious_session": thresholds["commands"] = 2
                        if profile_category == "multi_protocol": thresholds["protocols"] = 2
                    # Exercise the existing incident correlator against an isolated
                    # per-run SQLite file; operational incident state is untouched.
                    try:
                        with TemporaryDirectory(prefix="honeypot-experiment-incident-") as isolated:
                            incident_detector = IncidentService(SQLiteIncidentStorage(Path(isolated) / "incidents.sqlite3"))
                            result, elapsed = self._evaluate_scenario(scenario, repetition, scenario_seed, mode_events, mode, strategy, reason, profile_category if mode != "baseline" else None, thresholds, incident_detector)
                    except Exception as exc:
                        result = ScenarioResult(
                            scenario=scenario, repetition=repetition, seed=scenario_seed,
                            ground_truth="mixed" if any(not event.suspicious for event in generated) else "suspicious",
                            mode=mode, profile_category=profile_category if mode == "adaptive" else None,
                            selected_strategy=strategy, adaptation_reason=reason,
                            events_generated=len(generated), events_captured=None,
                            suspicious_events=sum(event.suspicious for event in generated),
                            true_positives=None, false_positives=None, false_negatives=None,
                            incident_detected=None, detection_latency_seconds=None,
                            processing_time_ms=None, completed=False,
                            errors=[f"Scenario processing failed ({type(exc).__name__}); measurements unavailable."],
                        )
                        elapsed = None
                    if result.completed:
                        simulated_events = [*generated, *followups]
                        virtual_duration = (
                            max(item.occurred_at for item in simulated_events)
                            - min(item.occurred_at for item in simulated_events)
                        ).total_seconds() if simulated_events else 0.0
                        result = result.model_copy(update={
                            "attacker_reactions": reactions,
                            "simulated_attacker_engaged": any(item not in {"abandon", "no_interaction"} for item in reactions),
                            "simulated_interaction_depth": len(simulated_events),
                            "simulated_session_duration_seconds": virtual_duration,
                            # No event currently carries a validated decoy asset ID.
                            "unique_decoys_accessed": None,
                            **({"policy_version": POLICY_VERSION} if mode == "closed_loop" else {}),
                        })
                    if result.completed and mode == "closed_loop":
                        reward = strategy_reward(
                            true_positives=result.true_positives or 0,
                            suspicious_events=result.suspicious_events,
                            false_positives=result.false_positives or 0,
                            benign_events=result.events_generated - result.suspicious_events,
                            incident_detected=result.incident_detected is True,
                            reactions=reactions,
                            reaction_events=result.events_generated - original_event_count,
                            original_events=original_event_count,
                            strategy=strategy,
                        )
                        result = result.model_copy(update={"strategy_reward": reward})
                        closed_loop_policy.update(strategy, reward)
                    elif mode == "closed_loop":
                        result = result.model_copy(update={"policy_version": POLICY_VERSION, "attacker_reactions": reactions})
                    rows.append(result.model_copy(update={"processing_time_ms": elapsed}) if result.completed else result)
        modes = [self._aggregate(mode, rows, len(request.scenarios) * request.repetitions) for mode in request.modes]
        baseline = next((item for item in modes if item.mode == "baseline"), None)
        adaptive = next((item for item in modes if item.mode == "adaptive"), None)
        closed_loop = next((item for item in modes if item.mode == "closed_loop"), None)
        comparison = self._compare(baseline, adaptive, closed_loop)
        result = ExperimentResult(
            experiment_id=experiment_id, created_at=datetime.now(timezone.utc), seed=request.seed,
            scenarios=request.scenarios, repetitions=request.repetitions, modes=request.modes,
            mode_definitions={name: MODE_DEFINITIONS[name] for name in request.modes},
            mode_metrics=modes, scenario_results=rows, comparison=comparison,
            metric_definitions=METRIC_DEFINITIONS,
            limitations=[
                "All events and labels are synthetic; results do not establish real-world detection or prevention effectiveness.",
                "The model classifier is trained on the existing deterministic synthetic dataset; category output is not evidence of attacker intent.",
                "Adaptation changes only the experiment-local detector thresholds and records the selected strategy; no live policy, decoy registry, event store, or ledger is mutated.",
                "Event capture measures local processing only. Network delivery, sensor loss, authentication, and incident-store behavior are outside this harness.",
                "Confidence intervals and process memory are unavailable; repetitions are bounded and are not treated as a statistical sample by default.",
            ], execution_time_seconds=round(perf_counter() - started, 6),
        )
        try:
            self.storage.save(result)
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Experiment ID has already been used") from None
        except Exception:
            raise HTTPException(503, "Experiment could not be persisted; no existing experiment was overwritten") from None
        return result

    @staticmethod
    def _evaluate_scenario(scenario, repetition, seed, events, mode, strategy, reason, category, thresholds, incident_detector=None):
        failed_auth = 0; ports = set(); commands = 0; protocols = set(); sensors = set()
        predictions: list[bool] = []; first_detection = None; incident_found = False
        # Start only after per-run incident storage has been initialized. This
        # measures the event-processing loop, including local correlation.
        started = perf_counter()
        for event in events:
            if event.attributes.get("authentication_outcome") == "failed": failed_auth += 1
            if event.destination_port is not None: ports.add(event.destination_port)
            if event.attributes.get("command_attempt") is True: commands += 1
            if event.protocol: protocols.add(event.protocol.casefold())
            sensors.add(event.sensor_id)
            flagged = (
                (event.source_system == "suricata" and event.event_type == "suricata_alert" and event.severity in {"high", "critical"})
                or failed_auth >= thresholds["auth"]
                or len(ports) >= thresholds["ports"]
                or commands >= thresholds["commands"]
                or len(protocols) >= thresholds["protocols"]
                or len(sensors) >= thresholds["sensors"]
            )
            predictions.append(flagged)
            incident = incident_detector.inspect(_as_events([event])[0]) if incident_detector else None
            incident_found = incident_found or incident is not None
            if flagged and first_detection is None:
                first_detection = max(0.0, (event.occurred_at - events[0].occurred_at).total_seconds())
        suspicious = sum(event.suspicious for event in events)
        tp = sum(pred and event.suspicious for pred, event in zip(predictions, events))
        fp = sum(pred and not event.suspicious for pred, event in zip(predictions, events))
        fn = suspicious - tp
        # Local incident correlation may perform SQLite work inside this loop.
        elapsed = (perf_counter() - started) * 1000
        return ScenarioResult(
            scenario=scenario, repetition=repetition, seed=seed,
            ground_truth="mixed" if any(not e.suspicious for e in events) else "suspicious",
            mode=mode, profile_category=category, selected_strategy=strategy,
            adaptation_reason=reason, events_generated=len(events), events_captured=len(events),
            suspicious_events=suspicious, true_positives=tp, false_positives=fp,
            false_negatives=fn, incident_detected=incident_found,
            detection_latency_seconds=first_detection, processing_time_ms=round(elapsed, 6), completed=True,
        ), elapsed

    @staticmethod
    def _aggregate(mode, rows, requested):
        selected = [row for row in rows if row.mode == mode]
        events = sum(r.events_generated for r in selected)
        captured = sum(r.events_captured or 0 for r in selected)
        suspicious = sum(r.suspicious_events for r in selected)
        tp = sum(r.true_positives or 0 for r in selected); fp = sum(r.false_positives or 0 for r in selected)
        fn = sum(r.false_negatives or 0 for r in selected)
        benign = sum(r.events_generated - r.suspicious_events for r in selected)
        suspicious_scenarios = [r for r in selected if r.suspicious_events]
        latencies = [r.detection_latency_seconds for r in suspicious_scenarios if r.detection_latency_seconds is not None]
        prediction_complete = all(r.true_positives is not None and r.false_positives is not None and r.false_negatives is not None for r in selected)
        incident_complete = all(r.incident_detected is not None for r in suspicious_scenarios)
        capture_complete = all(r.events_captured is not None for r in selected)
        timing_rows = [r.processing_time_ms for r in selected if r.processing_time_ms is not None]
        simulation_complete = all(
            r.completed
            and r.simulated_attacker_engaged is not None
            and r.simulated_interaction_depth is not None
            and r.simulated_session_duration_seconds is not None
            for r in selected
        )
        adaptive_runs = [r for r in selected if r.mode in {"adaptive", "closed_loop"}]
        applied = sum(r.selected_strategy not in {"neutral_response", "static_baseline"} for r in adaptive_runs)
        completed = sum(r.completed for r in selected)
        return ModeMetrics(
            mode=mode, scenarios_requested=requested, scenarios_completed=completed,
            scenario_completion_rate=completed / requested if requested else None,
            events_generated=events, events_captured=captured if capture_complete else None,
            event_capture_rate=(captured / events if events else None) if capture_complete else None,
            ground_truth_suspicious_events=suspicious, detector_true_positives=tp if prediction_complete else None,
            detector_false_positives=fp if prediction_complete else None, detector_false_negatives=fn if prediction_complete else None,
            detection_coverage=tp / suspicious if suspicious and prediction_complete else None,
            incident_detection_rate=(sum(r.incident_detected is True for r in suspicious_scenarios) / len(suspicious_scenarios) if suspicious_scenarios else None) if incident_complete else None,
            detection_latency_median_seconds=median(latencies) if latencies and all(r.completed for r in suspicious_scenarios) else None,
            false_positive_rate=fp / benign if benign and prediction_complete else None,
            false_negative_rate=fn / suspicious if suspicious and prediction_complete else None,
            adaptation_frequency=applied / len(adaptive_runs) if adaptive_runs else (0.0 if mode == "baseline" else None),
            adaptations_applied=applied,
            strategy_selection_counts={strategy: sum(r.selected_strategy == strategy for r in selected) for strategy in sorted({r.selected_strategy for r in selected})},
            attacker_reaction_counts={reaction: sum(r.attacker_reactions.count(reaction) for r in selected) for reaction in sorted({reaction for r in selected for reaction in r.attacker_reactions})},
            mean_strategy_reward=(sum(r.strategy_reward for r in selected if r.strategy_reward is not None) / sum(r.strategy_reward is not None for r in selected)) if any(r.strategy_reward is not None for r in selected) else None,
            adaptation_effectiveness=None, average_event_processing_ms=sum(timing_rows) / events if events and len(timing_rows) == len(selected) else None,
            execution_time_seconds=sum(timing_rows) / 1000.0 if len(timing_rows) == len(selected) else None, peak_memory_bytes=None,
            simulated_engagement_rate=(sum(r.simulated_attacker_engaged is True for r in selected) / len(selected)) if selected and simulation_complete else None,
            mean_synthetic_interaction_depth=(sum(r.simulated_interaction_depth for r in selected) / len(selected)) if selected and simulation_complete else None,
            median_synthetic_session_duration_seconds=(median(r.simulated_session_duration_seconds for r in selected) if selected and simulation_complete else None),
            unique_decoys_accessed=(sum(r.unique_decoys_accessed for r in selected) if selected and all(r.unique_decoys_accessed is not None for r in selected) else None),
        )

    @staticmethod
    def _compare(baseline, adaptive, closed_loop=None):
        if baseline is None or adaptive is None:
            return ExperimentComparison(available=False, metrics=[], note="Both baseline and adaptive modes are required for a paired comparison.")
        names = ("detection_coverage", "event_capture_rate", "incident_detection_rate", "detection_latency_median_seconds", "false_positive_rate", "false_negative_rate", "scenario_completion_rate", "adaptation_frequency", "average_event_processing_ms", "simulated_engagement_rate", "mean_synthetic_interaction_depth", "median_synthetic_session_duration_seconds", "unique_decoys_accessed")
        rows = []
        for name in names:
            a = getattr(baseline, name); b = getattr(adaptive, name)
            delta = (b - a) if a is not None and b is not None else None
            pct = (delta / abs(a) * 100) if delta is not None and a != 0 else None
            closed_value = getattr(closed_loop, name) if closed_loop is not None else None
            rows.append(MetricDifference(metric=name, baseline=a, adaptive=b, closed_loop=closed_value, absolute_difference=delta, percentage_difference=pct))
        coverage_a, coverage_b = baseline.detection_coverage, adaptive.detection_coverage
        adaptive.adaptation_effectiveness = coverage_b - coverage_a if coverage_a is not None and coverage_b is not None else None
        effect = adaptive.adaptation_effectiveness
        rows.append(MetricDifference(metric="adaptation_effectiveness", baseline=0.0 if effect is not None else None, adaptive=effect, closed_loop=closed_loop.adaptation_effectiveness if closed_loop else None, absolute_difference=effect, percentage_difference=None))
        return ExperimentComparison(available=True, metrics=rows, note="Differences are adaptive minus baseline. When selected, closed_loop shows its measured aggregate separately. Percentage changes are omitted when the baseline is zero or unavailable; no confidence interval is claimed.")

    def report(self, experiment_id: str, format: str) -> tuple[str, str]:
        result = self.get(experiment_id)
        if format == "json": return result.model_dump_json(indent=2), "application/json"
        if format == "csv":
            output = io.StringIO()
            fields = ["row_type", "experiment_id", "created_at", "experiment_seed", "experiment_scenarios", "experiment_repetitions", "experiment_modes", "metadata_key", "scenario", "repetition", "seed", "mode", "mode_definition", "ground_truth", "profile_category", "selected_strategy", "adaptation_reason", "policy_version", "attacker_reactions", "strategy_reward", "events_generated", "events_captured", "suspicious_events", "true_positives", "false_positives", "false_negatives", "incident_detected", "detection_latency_seconds", "processing_time_ms", "completed", "errors", "simulated_attacker_engaged", "simulated_interaction_depth", "simulated_session_duration_seconds", "unique_decoys_accessed", "metric", "baseline", "adaptive", "closed_loop", "absolute_difference", "percentage_difference", "value"]
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            base_metadata = {"row_type": "metadata", "experiment_id": result.experiment_id, "created_at": result.created_at.isoformat(), "experiment_seed": result.seed, "experiment_scenarios": ";".join(result.scenarios), "experiment_repetitions": result.repetitions, "experiment_modes": ";".join(result.modes)}
            for name, definition in result.mode_definitions.items(): writer.writerow({**base_metadata, "metadata_key": f"mode_definition:{name}", "value": definition})
            for name, definition in result.metric_definitions.items(): writer.writerow({**base_metadata, "metadata_key": f"metric_definition:{name}", "value": definition})
            for index, limitation in enumerate(result.limitations, start=1): writer.writerow({**base_metadata, "metadata_key": f"limitation:{index}", "value": limitation})
            for mode in result.mode_metrics:
                for metric in ModeMetrics.model_fields:
                    if metric == "mode": continue
                    writer.writerow({"row_type": "aggregate", "experiment_id": result.experiment_id, "created_at": result.created_at.isoformat(), "experiment_seed": result.seed, "mode": mode.mode, "mode_definition": result.mode_definitions[mode.mode], "metric": metric, "value": getattr(mode, metric)})
            for metric in result.comparison.metrics:
                    writer.writerow({"row_type": "comparison", "experiment_id": result.experiment_id, "created_at": result.created_at.isoformat(), "experiment_seed": result.seed, "metric": metric.metric, "baseline": metric.baseline, "adaptive": metric.adaptive, "closed_loop": metric.closed_loop, "absolute_difference": metric.absolute_difference, "percentage_difference": metric.percentage_difference})
            for row in result.scenario_results:
                writer.writerow({"row_type": "scenario", "experiment_id": result.experiment_id, "created_at": result.created_at.isoformat(), "experiment_seed": result.seed, **row.model_dump()})
            return output.getvalue(), "text/csv"
        if format == "markdown":
            lines = [f"# Experiment {result.experiment_id}", "", f"Created: {result.created_at.isoformat()}  ", f"Seed: {result.seed}  ", f"Scenarios: {', '.join(result.scenarios)}  ", f"Repetitions per scenario: {result.repetitions}  ", f"Modes: {', '.join(result.modes)}", "", "## Mode definitions"]
            lines += [f"- **{name}**: {definition}" for name, definition in result.mode_definitions.items()]
            lines += ["", "## Metric definitions"]
            lines += [f"- **{name}**: {definition}" for name, definition in result.metric_definitions.items()]
            lines += ["", "## Mode results", "", "| Mode | Detection coverage | Capture rate | Incident rate | FP rate | FN rate | Completion | Simulated engagement | Mean synthetic depth | Median virtual duration s | Unique decoys accessed |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
            for row in result.mode_metrics:
                lines.append(f"| {row.mode} | {_pct(row.detection_coverage)} | {_pct(row.event_capture_rate)} | {_pct(row.incident_detection_rate)} | {_pct(row.false_positive_rate)} | {_pct(row.false_negative_rate)} | {_pct(row.scenario_completion_rate)} | {_pct(row.simulated_engagement_rate)} | {_num(row.mean_synthetic_interaction_depth)} | {_num(row.median_synthetic_session_duration_seconds)} | {_num(row.unique_decoys_accessed)} |")
            lines += ["", "## Comparison", result.comparison.note, "", "| Metric | Baseline | Adaptive | Closed loop | Difference | Change % |", "|---|---:|---:|---:|---:|---:|"]
            for row in result.comparison.metrics: lines.append(f"| {row.metric} | {_num(row.baseline)} | {_num(row.adaptive)} | {_num(row.closed_loop)} | {_num(row.absolute_difference)} | {_num(row.percentage_difference)} |")
            lines += ["", "## Scenario-level results", "", "| Scenario | Repetition | Mode | Strategy | TP | FP | FN | Latency s |", "|---|---:|---|---|---:|---:|---:|---:|"]
            for row in result.scenario_results: lines.append(f"| {row.scenario} | {row.repetition} | {row.mode} | {row.selected_strategy} | {row.true_positives} | {row.false_positives} | {row.false_negatives} | {_num(row.detection_latency_seconds)} |")
            lines += ["", "## Limitations", *[f"- {item}" for item in result.limitations], "", "## Reproduction", f"Repeat `POST /api/v1/experiments/run` with seed `{result.seed}`, scenarios `{', '.join(result.scenarios)}`, repetitions `{result.repetitions}`, and modes `{', '.join(result.modes)}`. Supply a new experiment ID to preserve this saved result. Timing fields are machine-dependent."]
            return "\n".join(lines) + "\n", "text/markdown"
        raise HTTPException(422, "Report format must be json, csv, or markdown")


def _pct(value): return "Unavailable" if value is None else f"{value * 100:.2f}%"
def _num(value): return "Unavailable" if value is None else f"{value:.6g}"
