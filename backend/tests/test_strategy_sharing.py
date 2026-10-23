import base64
import json
from hashlib import sha256
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

from app.events.models import HoneypotEvent
from app.events.store import EventStore
from app.honeypot.bundle_generator import BehaviorConditionedBundleGenerator
from app.intelligence.fingerprint_schema import to_shareable_export
from app.intelligence.service import BehavioralIntelligenceService
from app.strategy_sharing import (
    SIGNING_DOMAIN,
    StrategyShareRecord,
    StrategySharingService,
    StrategySharingStorage,
    calculate_record_digest,
    canonical_record_bytes,
    parse_trusted_keys,
    signing_payload,
)
from app.strategy_replication import SimulatedOrganizationNode


ORG = "simulated-org-a"
KEY_ID = "test-org-a-key-v1"


def source_bundle_and_export(strategy="credential_decoy"):
    events = EventStore()
    now = datetime.now(timezone.utc)
    events.add(HoneypotEvent(event_id="private-event-xyz", actor_id="private-actor-xyz", decoy_id="decoy-credential-001", action="attempt_login", timestamp=now))
    fingerprint = BehavioralIntelligenceService(events).analyze_actor("private-actor-xyz")
    bundle = BehaviorConditionedBundleGenerator().generate_bundle(fingerprint, strategy, "private free-text rationale")
    return bundle, to_shareable_export(fingerprint)


def make_service(tmp_path, evaluation_runner=None):
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    service = StrategySharingService(
        StrategySharingStorage(tmp_path / "sharing.sqlite3"),
        {KEY_ID: (ORG, public)},
        signer=private,
        signer_organization=ORG,
        evaluation_runner=evaluation_runner,
    )
    return service, private


def signed_record(service, strategy="credential_decoy"):
    bundle, export = source_bundle_and_export(strategy)
    return service.create_record(ORG, KEY_ID, strategy, export, bundle)


def resign(record, private, **updates):
    changed = record.model_copy(update=updates)
    fields = changed.model_dump(mode="json", exclude={"digest", "signature"})
    if "bundle_template" in updates:
        fields["bundle_template_sha256"] = sha256(json.dumps(
            fields["bundle_template"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")).hexdigest()
    digest = calculate_record_digest(fields)
    unsigned = {**fields, "digest": digest}
    signature = base64.b64encode(private.sign(
        b"decentralized-honeypot:strategy-sharing:v1\0"
        + canonical_record_bytes(unsigned) + b"\0" + digest.encode("ascii")
    )).decode("ascii")
    return StrategyShareRecord.model_validate_json(json.dumps({**unsigned, "signature": signature}))


def test_canonicalization_digest_and_privacy_projection(tmp_path):
    service, _ = make_service(tmp_path)
    record = signed_record(service)
    data = record.model_dump(mode="json")
    assert canonical_record_bytes(data) == canonical_record_bytes(dict(reversed(list(data.items()))))
    assert record.digest == calculate_record_digest(record)
    assert signing_payload(record).startswith(SIGNING_DOMAIN)
    with pytest.raises(InvalidSignature):
        service.signer.public_key().verify(
            base64.b64decode(record.signature),
            signing_payload(record)[len(SIGNING_DOMAIN):],
        )
    serialized = record.model_dump_json()
    for private_value in ("private-actor-xyz", "private-event-xyz", "private free-text rationale", "actor_id", "event_id", "scenario_id", "credentials"):
        assert private_value not in serialized
    assert "bundle_template" in serialized
    assert "asset_types" in serialized


def test_import_verifies_and_persists_pending_then_rejects_duplicate(tmp_path):
    service, _ = make_service(tmp_path)
    record = signed_record(service)
    imported = service.import_record(record.model_dump(mode="json"))
    assert imported.state == "pending"
    assert imported.signature_valid and imported.bundle_valid
    with pytest.raises(HTTPException) as error:
        service.import_record(record.model_dump(mode="json"))
    assert error.value.status_code == 409
    with pytest.raises(HTTPException) as error:
        service.activate(record.record_id)
    assert error.value.status_code == 409
    with pytest.raises(HTTPException) as error:
        service.import_record(None)
    assert error.value.status_code == 422


def test_concurrent_duplicate_imports_store_one_pending_record(tmp_path):
    service, _ = make_service(tmp_path)
    payload = signed_record(service).model_dump(mode="json")

    def attempt_import(_):
        try:
            return service.import_record(payload).state
        except HTTPException as exc:
            return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt_import, range(2)))
    assert set(results) == {409, "pending"}
    assert service.storage.get(payload["record_id"])["state"] == "pending"


def test_trust_configuration_rejects_malformed_missing_and_mismatched_keys(tmp_path):
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    trusted = parse_trusted_keys(json.dumps({KEY_ID: {"organization_id": ORG, "public_key": public_pem}}))
    assert trusted[KEY_ID][0] == ORG
    for malformed in ("not-json", "[]", json.dumps({"k": {"organization_id": ORG, "public_key": "bad pem"}}), json.dumps({"k": {"organization_id": ORG}})):
        with pytest.raises(ValueError, match="TRUSTED_KEYS is invalid"):
            parse_trusted_keys(malformed)

    signer = StrategySharingService(StrategySharingStorage(tmp_path / "signer.sqlite3"), {KEY_ID: (ORG, private.public_key())}, private, ORG)
    record = signed_record(signer)
    missing = StrategySharingService(StrategySharingStorage(tmp_path / "missing.sqlite3"), {})
    with pytest.raises(HTTPException, match="not trusted"):
        missing.import_record(record.model_dump(mode="json"))
    mismatched_org = StrategySharingService(StrategySharingStorage(tmp_path / "mismatch.sqlite3"), {KEY_ID: ("different-org", private.public_key())})
    with pytest.raises(HTTPException, match="not trusted for this organization"):
        mismatched_org.import_record(record.model_dump(mode="json"))
    wrong_key = StrategySharingService(StrategySharingStorage(tmp_path / "wrong-key.sqlite3"), {KEY_ID: (ORG, Ed25519PrivateKey.generate().public_key())})
    with pytest.raises(HTTPException, match="signature is invalid"):
        wrong_key.import_record(record.model_dump(mode="json"))


def test_import_and_status_api_routes_use_configured_service(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.api import routes
    from app.main import app

    service, _ = make_service(tmp_path)
    record = signed_record(service)
    monkeypatch.setattr(routes, "strategy_sharing_service", service)
    client = TestClient(app)
    imported = client.post("/api/v1/strategy-sharing/imports", json=record.model_dump(mode="json"))
    assert imported.status_code == 201
    assert imported.json()["state"] == "pending"
    fetched = client.get(f"/api/v1/strategy-sharing/imports/{record.record_id}")
    assert fetched.status_code == 200
    assert fetched.json()["digest"] == record.digest
    evaluated = service.evaluate(record.record_id)
    assert evaluated.state in {"evaluated", "evaluation_failed"}
    status = client.get(f"/api/v1/strategy-sharing/imports/{record.record_id}").json()
    if status["evaluation"] is not None:
        assert status["evaluation"]["runs"] == []
        assert "actor_id" not in json.dumps(status["evaluation"])


def test_importing_sharing_module_does_not_initialize_its_database():
    import app.strategy_sharing as sharing

    database = __import__("pathlib").Path(sharing.__file__).resolve().parents[2] / "data" / "strategy_sharing.sqlite3"
    assert not database.exists()
    assert sharing.strategy_sharing_service._service is None


def test_digest_signature_and_untrusted_key_rejections(tmp_path):
    service, _ = make_service(tmp_path)
    record = signed_record(service).model_dump(mode="json")
    record["strategy"] = "file_decoy"
    with pytest.raises(HTTPException, match="digest mismatch"):
        service.import_record(record)
    record = signed_record(service).model_dump(mode="json")
    record["signature"] = base64.b64encode(b"bad-signature").decode()
    with pytest.raises(HTTPException, match="signature is invalid"):
        service.import_record(record)
    untrusted = StrategySharingService(StrategySharingStorage(tmp_path / "untrusted.sqlite3"), {})
    with pytest.raises(HTTPException, match="not trusted"):
        untrusted.import_record(signed_record(service).model_dump(mode="json"))
    record = signed_record(service).model_dump(mode="json")
    record["bundle_template_sha256"] = "0" * 64
    with pytest.raises(HTTPException, match="Bundle template digest mismatch"):
        service.import_record(record)


def test_bundle_tampering_and_schema_version_are_rejected(tmp_path):
    service, private = make_service(tmp_path)
    record = signed_record(service)
    altered_template = record.bundle_template.model_copy(update={"asset_types": ["files"], "relationship_types": ["has_file"]})
    altered = resign(record, private, bundle_template=altered_template)
    with pytest.raises(HTTPException, match="template is incomplete"):
        service.import_record(altered.model_dump(mode="json"))
    unknown = record.model_dump(mode="json")
    unknown["schema_version"] = 2
    with pytest.raises(HTTPException, match="Unsupported strategy-sharing schema version"):
        service.import_record(unknown)
    extra = record.model_dump(mode="json")
    extra["actor_id"] = "must-not-be-accepted"
    with pytest.raises(HTTPException, match="Invalid strategy-sharing schema"):
        service.import_record(extra)


def test_real_isolated_evaluation_preserves_result_and_requires_explicit_activation(tmp_path):
    service, _ = make_service(tmp_path)
    record = signed_record(service)
    service.import_record(record.model_dump(mode="json"))
    evaluated = service.evaluate(record.record_id)
    assert evaluated.state == "evaluated"
    assert evaluated.evaluation is not None
    assert evaluated.evaluation.status == "completed"
    assert evaluated.evaluation.overall.completed_runs == 5
    assert evaluated.evaluation.overall.strategy_selection_counts["credential_decoy"] > 0
    assert evaluated.evaluation_passed is True
    assert service.get(record.record_id).state == "evaluated"
    active = service.activate(record.record_id)
    assert active.state == "active"
    assert active.evaluation == evaluated.evaluation
    assert service.storage.get(record.record_id)["audit_json"].count('"event"') == 6
    with pytest.raises(HTTPException, match="passing local evaluation"):
        service.activate(record.record_id)


def test_failed_evaluation_stays_inactive_and_cannot_activate(tmp_path):
    service, _ = make_service(tmp_path, evaluation_runner=lambda _record: __import__("app.strategy_sharing", fromlist=["StrategySharingService"]).StrategySharingService._isolated_evaluate(_record).model_copy(update={"status": "partial"}))
    record = signed_record(service)
    service.import_record(record.model_dump(mode="json"))
    outcome = service.evaluate(record.record_id)
    assert outcome.state == "evaluation_failed"
    assert outcome.evaluation_passed is False
    with pytest.raises(HTTPException, match="passing local evaluation"):
        service.activate(record.record_id)


@pytest.mark.parametrize(
    "failure_case",
    [
        "partial",
        "failed_run",
        "incomplete_run",
        "missing_run_summary",
        "unrecorded_interaction",
        "bundle_validation_failure",
        "missing_bundle_measurement",
        "unvalidated_generated_bundle",
        "negative_strategy_count",
        "malformed_strategy_counts",
        "inconsistent_completion_rate",
        "inconsistent_recording_rate",
        "inconsistent_interaction_aggregate",
        "inconsistent_strategy_aggregate",
    ],
)
def test_evaluation_acceptance_fails_closed_on_incomplete_or_invalid_results(
    tmp_path, failure_case
):
    from app.evaluation.models import EvaluationMetrics
    from app.honeypot.bundles import BundleValidationIssue, BundleValidationResult

    injected_bundle_ids = []

    def evaluation_runner(record):
        result = StrategySharingService._isolated_evaluate(record)
        overall = result.overall
        if failure_case == "partial":
            return result.model_copy(update={"status": "partial"})
        if failure_case == "failed_run":
            overall = overall.model_copy(
                update={
                    "failed_runs": 1,
                    "completed_runs": overall.completed_runs - 1,
                    "errors": 1,
                }
            )
        elif failure_case == "incomplete_run":
            overall = overall.model_copy(
                update={
                    "incomplete_runs": 1,
                    "completed_runs": overall.completed_runs - 1,
                }
            )
        elif failure_case == "missing_run_summary":
            overall = overall.model_copy(
                update={"runs_with_summary": overall.runs_with_summary - 1}
            )
        elif failure_case == "unrecorded_interaction":
            overall = overall.model_copy(
                update={"interactions_recorded": overall.interactions_recorded - 1}
            )
        elif failure_case == "bundle_validation_failure":
            bundle_run = next(
                run
                for run in result.runs
                if run.simulation_summary is not None
                and run.simulation_summary.bundle_ids
            )
            assert bundle_run.simulation_summary is not None
            generated_bundle_id = bundle_run.simulation_summary.bundle_ids[0]
            injected_bundle_ids.append(generated_bundle_id)
            failed_result = BundleValidationResult(
                bundle_id=generated_bundle_id,
                schema_version=1,
                valid=False,
                issues=[BundleValidationIssue(code="test", message="invalid bundle")],
            )
            run_summary = bundle_run.simulation_summary.model_copy(
                update={
                    "bundle_validation_results": [
                        validation
                        for validation in bundle_run.simulation_summary.bundle_validation_results
                        if validation.bundle_id != generated_bundle_id
                    ]
                    + [failed_result]
                }
            )
            runs = [
                run.model_copy(update={"simulation_summary": run_summary})
                if run is bundle_run
                else run
                for run in result.runs
            ]
            overall = overall.model_copy(
                update={"bundle_validation_failures": 1}
            )
            result = result.model_copy(update={"runs": runs})
        elif failure_case == "missing_bundle_measurement":
            # Older summary payloads may omit this defaulted field. Parsing
            # supplies zero, but the field-set check must treat it as unknown.
            metrics_data = overall.model_dump()
            metrics_data.pop("bundle_validation_failures")
            overall = EvaluationMetrics.model_validate(metrics_data)
        elif failure_case == "unvalidated_generated_bundle":
            overall = overall.model_copy(
                update={"validated_bundles": overall.validated_bundles - 1}
            )
        elif failure_case == "negative_strategy_count":
            overall = overall.model_copy(
                update={
                    "strategy_selection_counts": {
                        record.strategy: 1,
                        "other_strategy": -1,
                    }
                }
            )
        elif failure_case == "malformed_strategy_counts":
            overall = overall.model_copy(
                update={
                    "strategy_selection_counts": {
                        "": 1,
                        record.strategy: 1,
                    }
                }
            )
        elif failure_case == "inconsistent_completion_rate":
            overall = overall.model_copy(update={"completion_rate": 0.5})
        elif failure_case == "inconsistent_recording_rate":
            overall = overall.model_copy(update={"event_recording_rate": 0.5})
        elif failure_case == "inconsistent_interaction_aggregate":
            first_run = result.runs[0]
            assert first_run.simulation_summary is not None
            changed_summary = first_run.simulation_summary.model_copy(
                update={
                    "interactions_recorded": (
                        first_run.simulation_summary.interactions_recorded - 1
                    )
                }
            )
            result = result.model_copy(
                update={
                    "runs": [
                        first_run.model_copy(
                            update={"simulation_summary": changed_summary}
                        ),
                        *result.runs[1:],
                    ]
                }
            )
        elif failure_case == "inconsistent_strategy_aggregate":
            strategy_counts = dict(overall.strategy_selection_counts)
            strategy_counts[record.strategy] += 1
            overall = overall.model_copy(
                update={"strategy_selection_counts": strategy_counts}
            )

        return result.model_copy(update={"overall": overall})

    service, _ = make_service(tmp_path, evaluation_runner=evaluation_runner)
    record = signed_record(service)
    service.import_record(record.model_dump(mode="json"))

    outcome = service.evaluate(record.record_id)

    assert outcome.state == "evaluation_failed"
    assert outcome.evaluation is not None
    assert outcome.evaluation_passed is False
    if failure_case == "bundle_validation_failure":
        assert outcome.evaluation.status == "completed"
        assert outcome.evaluation.overall.bundle_validation_failures == 1
        assert outcome.evaluation.runs == []
        stored_evaluation = json.loads(
            service.storage.get(record.record_id)["evaluation_json"]
        )
        assert any(
            validation["bundle_id"] == injected_bundle_ids[0]
            and validation["valid"] is False
            for run in stored_evaluation["runs"]
            for validation in run["simulation_summary"]["bundle_validation_results"]
        )
    with pytest.raises(HTTPException, match="passing local evaluation"):
        service.activate(record.record_id)


def test_evaluation_exception_is_audited_without_fabricated_metrics(tmp_path):
    service, _ = make_service(tmp_path, evaluation_runner=lambda _record: (_ for _ in ()).throw(RuntimeError("temporary failure")))
    record = signed_record(service)
    service.import_record(record.model_dump(mode="json"))
    with pytest.raises(HTTPException, match="Local strategy evaluation failed"):
        service.evaluate(record.record_id)
    row = service.storage.get(record.record_id)
    assert row["state"] == "evaluation_failed"
    assert row["evaluation_json"] is None
    assert "evaluation_execution_error" in row["audit_json"]
    with pytest.raises(HTTPException, match="passing local evaluation"):
        service.activate(record.record_id)


def test_evaluation_uses_only_temp_databases(tmp_path, monkeypatch):
    service, _ = make_service(tmp_path)
    record = signed_record(service)
    from app.adaptation.service import adaptive_honeypot_service
    from app.events.store import event_store as global_event_store
    from app.honeypot.registry import generated_decoy_registry
    from app.ledger.service import event_ledger

    def unexpected(*_args, **_kwargs):
        pytest.fail("isolated evaluation touched application-global state")

    monkeypatch.setattr(global_event_store, "add_event", unexpected)
    monkeypatch.setattr(event_ledger, "append", unexpected)
    monkeypatch.setattr(generated_decoy_registry, "save_bundle", unexpected)
    monkeypatch.setattr(adaptive_honeypot_service._history_storage, "append_decision", unexpected)
    result = service._isolated_evaluate(record)
    assert result.status == "completed"
    assert result.overall.interactions_recorded == result.overall.interactions_attempted
    # The only storage owned by this test service is its isolated sharing DB.
    assert service.storage.path == tmp_path / "sharing.sqlite3"
    assert service.storage.get(record.record_id) is None


def test_two_organization_replication_and_untrusted_third_node(tmp_path):
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    key_c = Ed25519PrivateKey.generate()
    org_a = ("simulated-org-a", "org-a-key-v1")
    org_b = ("simulated-org-b", "org-b-key-v1")
    org_c = ("simulated-org-c", "org-c-key-v1")
    node_a = SimulatedOrganizationNode(
        *org_a,
        tmp_path / "node-a.sqlite3",
        {org_a[1]: (org_a[0], key_a.public_key())},
        private_key=key_a,
    )
    node_b = SimulatedOrganizationNode(
        *org_b,
        tmp_path / "node-b.sqlite3",
        {
            org_b[1]: (org_b[0], key_b.public_key()),
            org_a[1]: (org_a[0], key_a.public_key()),
        },
        private_key=key_b,
    )
    node_c = SimulatedOrganizationNode(
        *org_c,
        tmp_path / "node-c.sqlite3",
        {org_c[1]: (org_c[0], key_c.public_key())},
        private_key=key_c,
    )

    bundle, fingerprint_export = source_bundle_and_export()
    record = node_a.export("credential_decoy", fingerprint_export, bundle)
    payload = node_a.transfer_payload(record)
    assert record.organization_id == node_a.organization_id
    node_public_keys = {
        node.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        for node in (node_a, node_b, node_c)
    }
    assert len(node_public_keys) == 3
    assert "private_key" not in json.dumps(payload).lower()

    tampered = dict(payload)
    tampered["strategy"] = "file_decoy"
    with pytest.raises(HTTPException, match="digest mismatch"):
        node_b.receive(tampered)
    assert node_b._service.storage.get(record.record_id) is None

    with pytest.raises(HTTPException, match="not trusted"):
        node_c.receive(payload)
    received = node_b.receive(payload)
    assert received.state == "pending"
    with pytest.raises(HTTPException) as duplicate:
        node_b.receive(payload)
    assert duplicate.value.status_code == 409

    evaluated = node_b.evaluate(record.record_id)
    assert evaluated.state == "evaluated"
    assert evaluated.evaluation is not None
    assert evaluated.evaluation.status == "completed"
    assert node_b.status(record.record_id).state == "evaluated"
    approved = node_b.approve(record.record_id)
    assert approved.state == "active"
    assert node_a.stored_record(record.record_id) is None
    assert node_c.stored_record(record.record_id) is None
    assert node_b.stored_record(record.record_id).organization_id == org_a[0]
    assert len({node_a.database_path, node_b.database_path, node_c.database_path}) == 3
    assert node_a.database_path.exists() and node_b.database_path.exists() and node_c.database_path.exists()
