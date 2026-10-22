from datetime import datetime, timezone

import pytest

from app.honeypot.bundle_generator import BehaviorConditionedBundleGenerator
from app.honeypot.bundles import BundleConsistencyValidator
from app.honeypot.registry import GeneratedDecoyRegistry
from app.intelligence.service import BehavioralFingerprint


def fingerprint(actor_id="bundle-test-actor", **overrides):
    values = {
        "actor_id": actor_id,
        "event_count": 2,
        "unique_decoys_accessed": 2,
        "unique_actions": 2,
        "action_sequence": ["read", "attempt_login"],
        "action_frequencies": {"read": 1, "attempt_login": 1},
        "decoy_types_accessed": ["file", "credential"],
        "decoy_type_frequencies": {"file": 1, "credential": 1},
        "credential_probing": True,
        "database_probing": False,
        "file_probing": True,
        "repeated_access": False,
        "first_seen": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
        "risk_score": 2,
        "risk_level": "medium",
        "reasons": [],
    }
    values.update(overrides)
    return BehavioralFingerprint(**values)


def test_generator_creates_consistent_credential_and_file_bundle():
    source = fingerprint()
    generator = BehaviorConditionedBundleGenerator()
    bundle = generator.generate_bundle(source, "credential_decoy", "login observed")

    assert BundleConsistencyValidator().validate(bundle).valid
    assert len(bundle.identities) == 1
    assert len(bundle.files) == 1
    assert len(bundle.api_resources) == 1
    assert not bundle.database_records
    assert bundle.identities[0].employee_id == bundle.files[0].employee_id
    assert {item.decoy_id for item in generator.to_generated_decoys(bundle)} == {
        bundle.identities[0].asset_id, bundle.files[0].asset_id
    }


def test_validator_reports_relationship_and_canonical_mismatch():
    bundle = BehaviorConditionedBundleGenerator().generate_bundle(
        fingerprint(), "credential_decoy", "login observed"
    )
    identity = bundle.identities[0].model_copy(update={"project_code": "LAB-WRONG"})
    broken = bundle.model_copy(update={"identities": [identity]})

    result = BundleConsistencyValidator().validate(broken)
    assert not result.valid
    assert "canonical_value_mismatch" in {issue.code for issue in result.issues}


def test_validator_rejects_dangling_relationship_and_unknown_schema():
    bundle = BehaviorConditionedBundleGenerator().generate_bundle(
        fingerprint(), "credential_decoy", "login observed"
    )
    broken_relation = bundle.relationships[0].model_copy(
        update={"target_asset_id": "missing-asset"}
    )
    broken = bundle.model_copy(
        update={"relationships": [broken_relation], "schema_version": 2}
    )
    codes = {
        issue.code
        for issue in BundleConsistencyValidator().validate(broken).issues
    }
    assert "unsupported_schema_version" in codes
    assert "dangling_relationship" in codes


def test_registry_persists_bundle_and_decoys_atomically(tmp_path):
    registry = GeneratedDecoyRegistry(tmp_path / "bundle-registry.sqlite3")
    generator = BehaviorConditionedBundleGenerator()
    bundle = generator.generate_bundle(fingerprint(), "credential_decoy", "login observed")
    decoys = generator.to_generated_decoys(bundle)

    assert registry.save_bundle(bundle, decoys) is True
    assert registry.get_bundle(bundle.bundle_id) == bundle
    assert len(registry.list_bundles(bundle.actor_id)) == 1
    assert {d.decoy_id for d in registry.list_all()} == {d.decoy_id for d in decoys}
    assert registry.save_bundle(bundle, decoys) is False


def test_registry_rolls_back_bundle_when_asset_insert_fails(tmp_path):
    registry = GeneratedDecoyRegistry(tmp_path / "bundle-rollback.sqlite3")
    generator = BehaviorConditionedBundleGenerator()
    bundle = generator.generate_bundle(fingerprint(), "credential_decoy", "login observed")
    decoys = generator.to_generated_decoys(bundle)
    with registry._connect() as connection:
        connection.execute(
            "CREATE TRIGGER reject_bundle_decoy BEFORE INSERT ON generated_decoys "
            "BEGIN SELECT RAISE(ABORT, 'test failure'); END"
        )

    with pytest.raises(Exception, match="test failure"):
        registry.save_bundle(bundle, decoys)
    assert registry.get_bundle(bundle.bundle_id) is None
    assert registry.list_all() == []


def test_ids_are_deterministic_per_fingerprint_and_isolated_by_actor():
    generator = BehaviorConditionedBundleGenerator()
    first = generator.generate_bundle(fingerprint(), "credential_decoy", "reason")
    same = generator.generate_bundle(fingerprint(), "credential_decoy", "reason")
    other = generator.generate_bundle(
        fingerprint(actor_id="different-actor"), "credential_decoy", "reason"
    )
    assert first.bundle_id == same.bundle_id
    assert first.bundle_id != other.bundle_id
