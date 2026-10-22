
from datetime import datetime, timezone

import pytest

from app.honeypot.generator import (
    BehaviorConditionedDecoyGenerator,
)
from app.intelligence.service import BehavioralFingerprint


@pytest.fixture
def generator():
    return BehaviorConditionedDecoyGenerator()


def make_fingerprint(
    *,
    actor_id="test-actor-01",
    actions=None,
    decoy_types=None,
    event_count=1,
    risk_level="low",
):
    now = datetime.now(timezone.utc)

    return BehavioralFingerprint(
        actor_id=actor_id,
        event_count=event_count,
        unique_decoys_accessed=len(decoy_types or []),
        unique_actions=len(set(actions or [])),
        action_sequence=actions or [],
        decoy_types_accessed=decoy_types or [],
        first_seen=now,
        last_seen=now,
        risk_score={"low": 10, "medium": 40, "high": 80}[risk_level],
        risk_level=risk_level,
        reasons=["Synthetic test fingerprint"],
    )


def test_login_attempt_generates_credential_decoy(generator):
    fingerprint = make_fingerprint(actions=["attempt_login"])

    decoys = generator.generate(fingerprint)

    assert decoys
    assert decoys[0].decoy_type == "credential"
    assert decoys[0].generation_strategy == "credential_focus"


def test_database_query_generates_database_decoy(generator):
    fingerprint = make_fingerprint(actions=["query"])

    decoys = generator.generate(fingerprint)

    assert decoys
    assert decoys[0].decoy_type == "database_record"
    assert decoys[0].generation_strategy == "database_focus"


def test_file_read_generates_file_decoy(generator):
    fingerprint = make_fingerprint(actions=["read"])

    decoys = generator.generate(fingerprint)

    assert decoys
    assert decoys[0].decoy_type == "file"
    assert decoys[0].generation_strategy == "file_focus"


def test_unknown_behavior_uses_safe_baseline(generator):
    fingerprint = make_fingerprint()

    decoys = generator.generate(fingerprint)

    assert decoys
    assert decoys[0].generation_strategy == "baseline_file"
    assert all(decoy.synthetic_only for decoy in decoys)


def test_high_risk_actor_gets_multiple_decoy_types(generator):
    fingerprint = make_fingerprint(
        actions=["attempt_login", "query", "read"],
        event_count=6,
        risk_level="high",
    )

    decoys = generator.generate(fingerprint)

    assert len(decoys) == 3
    assert {decoy.decoy_type for decoy in decoys} == {
        "credential",
        "database_record",
        "file",
    }


def test_generation_is_deterministic_for_same_fingerprint(generator):
    fingerprint = make_fingerprint(
        actor_id="repeatable-actor",
        actions=["attempt_login"],
    )

    first = generator.generate(fingerprint)
    second = generator.generate(fingerprint)

    assert [item.model_dump() for item in first] == [
        item.model_dump() for item in second
    ]


def test_generated_content_is_synthetic_and_has_no_real_secrets(generator):
    fingerprint = make_fingerprint(actions=["attempt_login"])

    decoys = generator.generate(fingerprint)

    for decoy in decoys:
        assert decoy.synthetic_only is True
        assert decoy.actor_id == fingerprint.actor_id
        assert decoy.content
        assert "INVALID_SYNTHETIC" in decoy.content.values()
        assert decoy.fingerprint_version == fingerprint.fingerprint_version
        assert decoy.generation_parameters["event_count"] == fingerprint.event_count
        assert any("Behavioral evidence" in reason for reason in decoy.rationale)


@pytest.mark.parametrize("limit", [0, -1, 11])
def test_invalid_generation_limit_is_rejected(generator, limit):
    fingerprint = make_fingerprint()

    with pytest.raises(ValueError, match="limit must be between 1 and 10"):
        generator.generate(fingerprint, limit=limit)


def test_generation_limit_is_respected(generator):
    fingerprint = make_fingerprint(
        actions=["attempt_login", "query", "read"],
        event_count=6,
        risk_level="high",
    )

    decoys = generator.generate(fingerprint, limit=2)

    assert len(decoys) == 2
