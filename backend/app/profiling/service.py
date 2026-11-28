"""Telemetry profile persistence and review-gated deception recommendations."""

from __future__ import annotations

import hashlib
import gc
import json
from math import isfinite
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable

import numpy as np
from fastapi import HTTPException

from app.events.store import EventStore
from app.incidents.storage import SQLiteIncidentStorage
from app.profiling.features import FEATURE_COLUMNS, FEATURE_SCHEMA_NAME, FEATURE_SCHEMA_VERSION, group_external_events
from app.profiling.models import (
    AttackerBehaviorProfile,
    DeceptionRecommendation,
    ProfileHistoryItem,
    RecommendationEvaluation,
    SafetyChecks,
    StatusAuditEntry,
)
from app.profiling.models_ml import ProfileModelError, load_model_bundle, validate_model_bundle
from app.profiling.storage import SQLiteProfileStorage


DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[3] / "experiments" / "results" / "attacker_profile_models.joblib"
MAX_HISTORY = 20
MIN_EVIDENCE_EVENTS = 3
MIN_FAILED_LOGINS_FOR_AUTH_PROBING = 3
MIN_DISTINCT_USERNAMES_FOR_AUTH_PROBING = 2
RECOMMENDATION_POLICY: dict[str, dict] = {
    "reconnaissance": {"strategy": "expanded_decoy_path", "action": "add_simulated_service_diversity", "title": "Increase simulated service diversity", "expected_scenario": "reconnaissance", "rationale": "Synthetic model classified reconnaissance-like connection behavior; vary only isolated simulated decoy paths."},
    "authentication_probing": {"strategy": "credential_decoy", "action": "add_synthetic_authentication_targets", "title": "Add synthetic authentication targets", "expected_scenario": "credential_probing", "rationale": "Authentication event aggregates support additional disabled synthetic login targets and audit opportunities."},
    "repeated_connection": {"strategy": "expanded_decoy_path", "action": "vary_simulated_response_paths", "title": "Vary simulated response paths", "expected_scenario": "repeated_access", "rationale": "Repeated connection aggregates support broader simulated response paths within the existing safe decoy catalog."},
    "suspicious_session": {"strategy": "file_decoy", "action": "add_simulated_session_observability", "title": "Add simulated session observability", "expected_scenario": "multi_stage", "rationale": "Session aggregates support richer metadata logging and inert synthetic file decoys; captured commands remain unused."},
    "multi_protocol": {"strategy": "expanded_decoy_path", "action": "add_protocol_diverse_synthetic_assets", "title": "Add protocol-diverse synthetic assets", "expected_scenario": "multi_stage", "rationale": "Observed protocol diversity supports additional simulated protocol representations without opening real services."},
    "unknown": {"strategy": "neutral_response", "action": "collect_more_telemetry", "title": "Collect more telemetry", "expected_scenario": None, "rationale": "Available evidence is insufficient for a behavior-specific deception recommendation."},
}
RISK_CONSTRAINTS = [
    "Approval records review state only; it does not deploy or enforce a policy.",
    "Generated assets must remain synthetic and isolated.",
    "Do not execute captured commands, passwords, or uploaded files.",
    "Do not expose public services or modify firewall/network controls.",
    "Predicted behavior categories do not establish intent.",
]


class AttackerProfileService:
    def __init__(self, event_store: EventStore, storage: SQLiteProfileStorage | None = None, *, incident_storage: SQLiteIncidentStorage | None = None, model_path: str | Path | None = None, model_bundle: dict | None = None, evaluation_runner: Callable | None = None) -> None:
        self._events = event_store
        self.storage = storage or SQLiteProfileStorage()
        self._incident_storage = incident_storage
        self.model_path = Path(model_path or os.getenv("HONEYPOT_PROFILE_MODEL_PATH") or DEFAULT_MODEL_PATH)
        self._model_bundle = validate_model_bundle(model_bundle) if model_bundle is not None else None
        self._evaluation_runner = evaluation_runner or self._run_isolated_evaluation

    def _models(self) -> dict:
        if self._model_bundle is not None:
            return self._model_bundle
        try:
            self._model_bundle = load_model_bundle(self.model_path)
        except ProfileModelError as exc:
            raise HTTPException(503, "Attacker profile model is unavailable or incompatible; train the local synthetic model first") from exc
        return self._model_bundle

    @property
    def model_version(self) -> str:
        return str(self._models()["metadata"]["model_version"])

    @staticmethod
    def _classification_with_evidence_gate(
        predicted: str,
        features: dict[str, int | float],
        observation_count: int,
    ) -> str:
        """Abstain when the predicted category's defining telemetry is absent.

        The classifier is trained on synthetic labels and cannot establish
        intent. These deterministic gates prevent a synthetic class vote from
        overriding missing real-event evidence. Thresholds mirror the
        generator's minimum class-defining features; they are policy checks,
        not learned or calibrated confidence thresholds.
        """
        if observation_count < MIN_EVIDENCE_EVENTS:
            return "unknown"

        evidence_requirements: dict[str, tuple[tuple[str, float], ...]] = {
            "reconnaissance": (("connection_count", 5), ("unique_destination_ports", 3)),
            "authentication_probing": (
                ("failed_auth_count", MIN_FAILED_LOGINS_FOR_AUTH_PROBING),
                ("unique_usernames_attempted", MIN_DISTINCT_USERNAMES_FOR_AUTH_PROBING),
            ),
            "repeated_connection": (("event_count", 12), ("connection_count", 10)),
            "suspicious_session": (("command_attempt_count", 3),),
            "multi_protocol": (("unique_protocol_count", 3),),
        }
        if predicted == "unknown":
            return "unknown"
        requirements = evidence_requirements.get(predicted)
        if requirements is None:
            return "unknown"
        if not all(features.get(name, 0) >= minimum for name, minimum in requirements):
            return "unknown"
        return predicted

    def recompute(self, window_seconds: int = 3600) -> tuple[list[AttackerBehaviorProfile], int]:
        if type(window_seconds) is not int or not 60 <= window_seconds <= 86400:
            raise HTTPException(422, "Observation window must be between 60 and 86400 seconds")
        bundle = self._models()
        all_events = self._events.list_events()
        aware_times = [event.timestamp.astimezone(timezone.utc) for event in all_events if event.source == "external" and event.source_ip and event.timestamp.tzinfo and event.timestamp.utcoffset() is not None]
        as_of = max(aware_times, default=datetime.now(timezone.utc))
        incident_records = self._incident_storage.profile_signals(since=(as_of - timedelta(seconds=window_seconds)).isoformat()) if self._incident_storage else []
        groups = group_external_events(all_events, window_seconds=window_seconds, as_of=as_of, incident_records=incident_records)
        profiles: list[AttackerBehaviorProfile] = []
        recommendations_created = 0
        metadata = bundle["metadata"]
        for source_ref, (_address, historical, features) in sorted(groups.items()):
            matrix = np.asarray([[float(features[name]) for name in FEATURE_COLUMNS]], dtype=np.float64)
            predicted = str(bundle["classifier"].predict(matrix)[0])
            probabilities = bundle["classifier"].predict_proba(matrix)[0]
            vote_fraction = float(max(probabilities))
            scaled = bundle["scaler"].transform(matrix)
            anomaly_score = float(bundle["anomaly_detector"].score_samples(scaled)[0])
            low = float(metadata["anomaly_baseline_p05"])
            high = float(metadata["anomaly_baseline_p95"])
            anomaly_index = 0.5 if high <= low else float(np.clip((high - anomaly_score) / (high - low), 0.0, 1.0))
            cluster = int(bundle["clusterer"].predict(scaled)[0])
            profile_id = "profile-" + source_ref[:32]
            prior = self.storage.get_profile(profile_id)
            classification = self._classification_with_evidence_gate(
                predicted, features, len(historical)
            )
            if prior is not None and prior.features == features and prior.classification == classification and prior.model_version == metadata["model_version"] and prior.observation_window_seconds == window_seconds:
                profiles.append(prior)
                recommendations_created += int(self.storage.add_recommendation(self._recommendation(prior)))
                continue
            changes = []
            if prior and prior.classification != classification:
                changes.append("classification_changed")
            if prior and prior.cluster != cluster:
                changes.append("cluster_changed")
            timestamps = [event.timestamp.astimezone(timezone.utc) for event in historical if event.timestamp.tzinfo and event.timestamp.utcoffset() is not None]
            if not timestamps:
                continue
            first_observed, last_observed = min(timestamps), max(timestamps)
            history = list(prior.history if prior else [])
            history.append(ProfileHistoryItem(recorded_at=datetime.now(timezone.utc), category=classification, anomaly_index=round(anomaly_index, 6), cluster=cluster, observation_count=len(historical), changes=changes))
            history = history[-MAX_HISTORY:]
            ranked = sorted(zip(FEATURE_COLUMNS, bundle["classifier"].feature_importances_), key=lambda pair: (-float(pair[1]), pair[0]))[:8]
            influential = {name: round(float(importance), 6) for name, importance in ranked}
            profile = AttackerBehaviorProfile(
                profile_id=profile_id, source_ref=source_ref,
                first_observed=first_observed, last_observed=last_observed,
                observation_count=len(historical), observation_window_seconds=window_seconds,
                feature_schema_name=FEATURE_SCHEMA_NAME, feature_schema_version=FEATURE_SCHEMA_VERSION,
                features=features, classification=classification,
                model_vote_fraction=round(vote_fraction, 6), anomaly_index=round(anomaly_index, 6),
                anomaly_index_method="synthetic_baseline_percentile", cluster=cluster,
                evidence_indicators=self._evidence(features), influential_features=influential,
                model_version=str(metadata["model_version"]), history=history,
                limitations=[
                    "Training labels are synthetic scenario labels, not confirmed maliciousness.",
                    "Model vote fraction and anomaly index are not calibrated probabilities.",
                    "Behavior categories are retained only when their defining aggregate evidence passes deterministic minimum gates; otherwise the result is unknown.",
                    "Source reference is a deterministic hash and is not anonymization.",
                ],
            )
            self.storage.upsert_profile(profile)
            profiles.append(profile)
            recommendations_created += int(self.storage.add_recommendation(self._recommendation(profile)))
        return profiles, recommendations_created

    @staticmethod
    def _evidence(features: dict[str, int | float]) -> list[str]:
        evidence = []
        checks = (
            ("failed_auth_count", "failed authentication events observed"),
            ("successful_auth_count", "successful authentication events observed"),
            ("command_attempt_count", "command attempts observed (content ignored)"),
            ("connection_count", "network connection or flow events observed"),
            ("suricata_alert_count", "Suricata alerts observed"),
            ("unique_destination_ports", "multiple destination ports observed"),
            ("unique_protocol_count", "protocol diversity observed"),
            ("sensor_count", "sensor sources observed"),
        )
        for key, label in checks:
            value = features.get(key, 0)
            if value > (1 if key in {"unique_destination_ports", "unique_protocol_count", "sensor_count"} else 0):
                evidence.append(label)
        if not evidence:
            evidence.append("external telemetry observed; behavior-specific evidence is limited")
        return evidence[:16]

    @staticmethod
    def _recommendation(profile: AttackerBehaviorProfile) -> DeceptionRecommendation:
        policy = RECOMMENDATION_POLICY[profile.classification]
        feature_order = ("failed_auth_count", "successful_auth_count", "session_count", "command_attempt_count", "connection_count", "unique_destination_ports", "suricata_alert_count", "unique_protocol_count", "sensor_count", "behavioral_diversity")
        support = {key: profile.features[key] for key in feature_order if profile.features.get(key, 0) != 0}
        support = dict(list(support.items())[:8])
        rationale = policy["rationale"]
        if support:
            rationale += " Supporting aggregate features: " + ", ".join(f"{name}={value:g}" for name, value in list(support.items())[:4]) + "."
        canonical = json.dumps({"profile": profile.profile_id, "category": profile.classification, "model": profile.model_version}, sort_keys=True, separators=(",", ":"))
        recommendation_id = "recommendation-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
        now = datetime.now(timezone.utc)
        return DeceptionRecommendation(
            recommendation_id=recommendation_id, profile_id=profile.profile_id,
            profile_category=profile.classification, proposed_strategy=policy["strategy"],
            action=policy["action"], title=policy["title"], rationale=rationale,
            supporting_features=support, expected_scenario=policy["expected_scenario"],
            model_version=profile.model_version, status="pending",
            status_history=[StatusAuditEntry(state="pending", changed_at=now, action="created")],
            risk_constraints=RISK_CONSTRAINTS,
            limitations=["Recommendation is advisory and does not alter the deployed policy.", "Simulation evaluation is synthetic workflow validation, not a real-world effectiveness study."],
        )

    def list_profiles(self, limit: int = 50, offset: int = 0):
        return self.storage.list_profiles(limit, offset)

    def get_profile(self, profile_id: str) -> AttackerBehaviorProfile:
        profile = self.storage.get_profile(profile_id)
        if profile is None:
            raise HTTPException(404, "Behavior profile not found")
        history_rows = self.storage.get_profile_history(profile_id)
        if history_rows:
            from app.profiling.models import ProfileHistoryItem
            profile = profile.model_copy(update={"history": [ProfileHistoryItem.model_validate(row) for row in reversed(history_rows)]})
        return profile

    def stats(self) -> dict:
        profiles = self.storage.stats()
        categories: dict[str, int] = {}
        clusters: dict[str, int] = {}
        scores = []
        versions = set()
        for row in profiles:
            category = str(row.get("classification", "unknown"))
            categories[category] = categories.get(category, 0) + 1
            cluster = str(row.get("cluster", "unknown"))
            clusters[cluster] = clusters.get(cluster, 0) + 1
            score = row.get("anomaly_index")
            if isinstance(score, (int, float)):
                scores.append(float(score))
            versions.add(row.get("model_version"))
        return {"total_profiles": len(profiles), "category_counts": categories, "cluster_counts": clusters, "mean_anomaly_index": round(sum(scores) / len(scores), 6) if scores else None, "model_version": sorted(versions)[0] if len(versions) == 1 else None}

    def list_recommendations(self, limit: int = 50, offset: int = 0):
        return self.storage.list_recommendations(limit, offset)

    def evaluate_recommendation(self, recommendation_id: str) -> DeceptionRecommendation:
        recommendation = self.storage.get_recommendation(recommendation_id)
        if recommendation is None:
            raise HTTPException(404, "Deception recommendation not found")
        if recommendation.status == "approved":
            raise HTTPException(409, "Approved recommendations cannot be re-evaluated")
        profile = self.storage.get_profile(recommendation.profile_id)
        if profile is None:
            raise HTTPException(409, "Recommendation profile is unavailable")
        try:
            summary = self._evaluation_runner()
            evaluation = self._summarize_evaluation(recommendation, profile, summary)
        except Exception:
            evaluation = self._failed_evaluation(recommendation, profile)
        status = "evaluated" if evaluation.outcome == "passed" else "evaluation_failed"
        updated = recommendation.model_copy(update={"status": status, "evaluation": evaluation, "status_history": [*recommendation.status_history, StatusAuditEntry(state=status, changed_at=evaluation.evaluated_at, action="evaluated" if status == "evaluated" else "evaluation_failed")][-20:]})
        if not self.storage.update_recommendation(updated, allowed_states=("pending", "evaluation_failed", "evaluated")):
            raise HTTPException(409, "Recommendation state changed during evaluation; reload and retry")
        return updated

    @staticmethod
    def _summarize_evaluation(recommendation: DeceptionRecommendation, profile: AttackerBehaviorProfile, summary) -> RecommendationEvaluation:
        overall = summary.overall
        measured = [scenario.scenario for scenario in summary.scenarios]
        expected_covered = bool(recommendation.expected_scenario and recommendation.expected_scenario in measured)
        evidence_sufficient = profile.observation_count >= MIN_EVIDENCE_EVENTS and profile.classification != "unknown"
        required_metrics = ("bundle_validation_failures", "decoys_generated", "event_recording_rate", "interactions_attempted", "interactions_recorded", "completed_runs", "failed_runs", "incomplete_runs", "runs_requested")
        measurements_available = all(name in overall.model_fields_set for name in required_metrics)
        count_metrics = (overall.runs_requested, overall.runs_with_summary, overall.completed_runs, overall.failed_runs, overall.incomplete_runs, overall.interactions_attempted, overall.interactions_recorded, overall.decoys_generated, overall.bundle_validation_failures)
        counts_valid = all(type(value) is int and value >= 0 for value in count_metrics)
        rate_valid = type(overall.event_recording_rate) in (int, float) and 0 <= overall.event_recording_rate <= 1
        run_rows_valid = len(summary.runs) == overall.runs_requested and all(
            run.status == "completed" and run.simulation_summary is not None
            and run.simulation_summary.interactions_attempted == run.simulation_summary.interactions_recorded
            and not run.simulation_summary.errors
            and len(run.simulation_summary.bundle_validation_results) == len(run.simulation_summary.bundle_ids)
            and all(validation.valid for validation in run.simulation_summary.bundle_validation_results)
            for run in summary.runs
        )
        expected_scenarios = {"reconnaissance", "credential_probing", "database_probing", "multi_stage", "repeated_access"}
        scenario_coverage_complete = len(measured) == len(expected_scenarios) and set(measured) == expected_scenarios
        elapsed_valid = type(summary.elapsed_seconds) in (int, float) and isfinite(summary.elapsed_seconds) and summary.elapsed_seconds >= 0
        runs_complete = measurements_available and counts_valid and elapsed_valid and scenario_coverage_complete and summary.status == "completed" and overall.runs_requested > 0 and overall.completed_runs == overall.runs_requested and overall.runs_with_summary == overall.runs_requested and overall.failed_runs == 0 and overall.incomplete_runs == 0 and run_rows_valid
        events_complete = measurements_available and counts_valid and rate_valid and overall.interactions_attempted > 0 and overall.interactions_recorded == overall.interactions_attempted and overall.event_recording_rate == 1.0
        bundles_valid = measurements_available and counts_valid and overall.bundle_validation_failures == 0
        passed = evidence_sufficient and expected_covered and runs_complete and events_complete and bundles_valid
        return RecommendationEvaluation(
            outcome="passed" if passed else "failed", evaluated_at=datetime.now(timezone.utc),
            evaluation_kind="isolated_synthetic_workflow_validation", measured_scenarios=measured,
            expected_scenario=recommendation.expected_scenario, expected_scenario_covered=expected_covered,
            runs_requested=overall.runs_requested if measurements_available else None,
            completed_runs=overall.completed_runs if measurements_available else None,
            failed_runs=overall.failed_runs if measurements_available else None,
            incomplete_runs=overall.incomplete_runs if measurements_available else None,
            interactions_attempted=overall.interactions_attempted if measurements_available else None,
            interactions_recorded=overall.interactions_recorded if measurements_available else None,
            event_recording_rate=overall.event_recording_rate if measurements_available else None,
            generated_decoys=overall.decoys_generated if "decoys_generated" in overall.model_fields_set else None,
            bundle_validation_failures=overall.bundle_validation_failures if "bundle_validation_failures" in overall.model_fields_set else None,
            elapsed_seconds=summary.elapsed_seconds,
            synthetic_interaction_opportunities=overall.interactions_recorded if measurements_available else None,
            telemetry_coverage="Unavailable: the existing simulator generates synthetic honeypot interactions, not native Zeek, Suricata, or Cowrie sensor traffic.",
            false_positive_risk="Unavailable: no labeled real-world validation set exists; a predicted category is not evidence of intent.",
            safety_checks=SafetyChecks(synthetic_assets_only=True, no_command_execution=True, no_public_deployment=True, no_automatic_blocking=True, bundle_validation_passed=bundles_valid, simulation_runs_complete=runs_complete, event_recording_complete=events_complete, evidence_sufficient=evidence_sufficient, expected_scenario_covered=expected_covered),
            limitations=["This gate validates the isolated synthetic workflow and required scenario presence only.", "It does not measure detection accuracy, telemetry-source coverage, real-world false positives, or deception effectiveness."],
        )

    @staticmethod
    def _failed_evaluation(recommendation: DeceptionRecommendation, profile: AttackerBehaviorProfile) -> RecommendationEvaluation:
        now = datetime.now(timezone.utc)
        evidence_sufficient = profile.observation_count >= MIN_EVIDENCE_EVENTS and profile.classification != "unknown"
        return RecommendationEvaluation(
            outcome="failed", evaluated_at=now, evaluation_kind="isolated_synthetic_workflow_validation",
            measured_scenarios=[], expected_scenario=recommendation.expected_scenario, expected_scenario_covered=False,
            runs_requested=None, completed_runs=None, failed_runs=None, incomplete_runs=None,
            interactions_attempted=None, interactions_recorded=None, event_recording_rate=None,
            generated_decoys=None, bundle_validation_failures=None, elapsed_seconds=None,
            synthetic_interaction_opportunities=None,
            telemetry_coverage="Unavailable: local simulation did not return a result.",
            false_positive_risk="Unavailable: no labeled real-world validation set exists.",
            safety_checks=SafetyChecks(synthetic_assets_only=True, no_command_execution=True, no_public_deployment=True, no_automatic_blocking=True, bundle_validation_passed=False, simulation_runs_complete=False, event_recording_complete=False, evidence_sufficient=evidence_sufficient, expected_scenario_covered=False),
            limitations=["The local evaluation did not produce a usable result; approval is blocked."],
        )

    def approve_recommendation(self, recommendation_id: str) -> DeceptionRecommendation:
        recommendation = self.storage.get_recommendation(recommendation_id)
        if recommendation is None:
            raise HTTPException(404, "Deception recommendation not found")
        if recommendation.status != "evaluated" or recommendation.evaluation is None or recommendation.evaluation.outcome != "passed":
            raise HTTPException(409, "Recommendation requires a passing evaluation before approval")
        now = datetime.now(timezone.utc)
        updated = recommendation.model_copy(update={"status": "approved", "status_history": [*recommendation.status_history, StatusAuditEntry(state="approved", changed_at=now, action="approved")][-20:]})
        if not self.storage.update_recommendation(updated, allowed_states=("evaluated",)):
            raise HTTPException(409, "Recommendation state changed before approval; reload and retry")
        return updated

    @staticmethod
    def _run_isolated_evaluation():
        from app.strategy_sharing import StrategySharingService
        with TemporaryDirectory(prefix="honeypot-profile-eval-") as temporary:
            try:
                result = StrategySharingService._run_isolated_evaluation(Path(temporary))
                return result
            finally:
                # Existing SQLite wrappers own short-lived connections which
                # Python may finalize only after their service objects die.
                gc.collect()
