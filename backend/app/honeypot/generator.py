from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.intelligence.service import BehavioralFingerprint


GeneratedDecoyType = Literal["file", "credential", "database_record"]


class GeneratedDecoy(BaseModel):
    """A synthetic decoy generated from an actor's behavior."""

    model_config = ConfigDict(frozen=True)

    decoy_id: str
    actor_id: str
    decoy_type: GeneratedDecoyType
    name: str
    description: str
    content: dict[str, str]
    generation_strategy: str
    rationale: list[str]
    synthetic_only: bool = True


class BehaviorConditionedDecoyGenerator:
    """Generate safe, synthetic decoys using behavioral fingerprints."""

    def generate(
        self,
        fingerprint: BehavioralFingerprint,
        limit: int = 3,
    ) -> list[GeneratedDecoy]:
        if not 1 <= limit <= 10:
            raise ValueError("limit must be between 1 and 10")

        actions = set(fingerprint.action_sequence)
        accessed_types = set(fingerprint.decoy_types_accessed)

        candidates: list[
            tuple[GeneratedDecoyType, str, list[str]]
        ] = []

        # Prioritize decoy types based on observed behavior.
        if "attempt_login" in actions or "credential" in accessed_types:
            candidates.append(
                (
                    "credential",
                    "credential_focus",
                    [
                        "Login attempt or previous credential-decoy access observed"
                    ],
                )
            )

        if "query" in actions or "database_record" in accessed_types:
            candidates.append(
                (
                    "database_record",
                    "database_focus",
                    [
                        "Database query or previous database-decoy access observed"
                    ],
                )
            )

        if "file" in accessed_types or "read" in actions:
            candidates.append(
                (
                    "file",
                    "file_focus",
                    [
                        "File access category or read action observed"
                    ],
                )
            )

        # Broaden coverage for high-risk or repeated activity.
        if (
            fingerprint.risk_level == "high"
            or fingerprint.event_count >= 5
        ):
            candidates.extend(
                [
                    (
                        "file",
                        "expanded_file_path",
                        [
                            "Repeated or high-risk activity; broaden synthetic decoy coverage"
                        ],
                    ),
                    (
                        "database_record",
                        "expanded_database_path",
                        [
                            "Repeated or high-risk activity; broaden synthetic decoy coverage"
                        ],
                    ),
                    (
                        "credential",
                        "expanded_credential_path",
                        [
                            "Repeated or high-risk activity; broaden synthetic decoy coverage"
                        ],
                    ),
                ]
            )

        fallback_types: list[GeneratedDecoyType] = [
            "credential",
            "database_record",
            "file",
        ]

        # Use baseline candidates when there is little behavioral evidence.
        if not candidates:
            candidates.extend(
                [
                    (
                        "file",
                        "baseline_file",
                        [
                            "No specific decoy preference identified; use a synthetic baseline"
                        ],
                    ),
                    (
                        "database_record",
                        "baseline_database",
                        [
                            "No specific decoy preference identified; use a synthetic baseline"
                        ],
                    ),
                    (
                        "credential",
                        "baseline_credential",
                        [
                            "No specific decoy preference identified; use a synthetic baseline"
                        ],
                    ),
                ]
            )

        # Supplemental candidates allow repeated types when necessary.
        for decoy_type in fallback_types:
            candidates.append(
                (
                    decoy_type,
                    f"supplemental_{decoy_type}",
                    [
                        "Supplemental synthetic decoy added to meet the requested coverage"
                    ],
                )
            )

        generated: list[GeneratedDecoy] = []
        selected_candidates: set[tuple[str, str]] = set()
        seen_types: set[str] = set()

        # Pass 1: prioritize diversity across decoy types.
        for decoy_type, strategy, rationale in candidates:
            if decoy_type in seen_types:
                continue

            generated.append(
                self._build_decoy(
                    fingerprint=fingerprint,
                    decoy_type=decoy_type,
                    strategy=strategy,
                    rationale=rationale,
                )
            )

            seen_types.add(decoy_type)
            selected_candidates.add((decoy_type, strategy))

            if len(generated) >= limit:
                return generated

        # Pass 2: use additional strategies, including repeated types.
        for decoy_type, strategy, rationale in candidates:
            if (decoy_type, strategy) in selected_candidates:
                continue

            generated.append(
                self._build_decoy(
                    fingerprint=fingerprint,
                    decoy_type=decoy_type,
                    strategy=strategy,
                    rationale=rationale,
                )
            )

            selected_candidates.add((decoy_type, strategy))

            if len(generated) >= limit:
                return generated

        # Pass 3: create more unique strategies if required.
        index = 1

        while len(generated) < limit:
            decoy_type = fallback_types[
                (index - 1) % len(fallback_types)
            ]
            strategy = f"supplemental_{decoy_type}_{index}"

            generated.append(
                self._build_decoy(
                    fingerprint=fingerprint,
                    decoy_type=decoy_type,
                    strategy=strategy,
                    rationale=[
                        "Additional synthetic decoy generated to meet the requested limit"
                    ],
                )
            )

            index += 1

        return generated

    @staticmethod
    def _build_decoy(
        fingerprint: BehavioralFingerprint,
        decoy_type: GeneratedDecoyType,
        strategy: str,
        rationale: list[str],
    ) -> GeneratedDecoy:
        # Stable IDs are derived from actor, type, strategy, and event count.
        identity = (
            f"{fingerprint.actor_id}|{decoy_type}|{strategy}|"
            f"{fingerprint.event_count}"
        )
        suffix = sha256(
            identity.encode("utf-8")
        ).hexdigest()[:12]

        if decoy_type == "file":
            name = f"internal_report_{suffix}.txt"
            description = (
                "Synthetic report created for honeypot testing."
            )
            content = {
                "document_id": f"DOC-{suffix.upper()}",
                "classification": "INTERNAL-SYNTHETIC",
                "summary": (
                    "Fictional operational report; contains no real records."
                ),
            }

        elif decoy_type == "credential":
            name = f"service_account_{suffix}"
            description = (
                "Synthetic credential-shaped decoy; not a usable secret."
            )
            content = {
                "username": f"synthetic_user_{suffix}",
                "credential_status": "INVALID_SYNTHETIC",
                "notice": (
                    "Placeholder only. Not valid for authentication."
                ),
            }

        else:
            name = f"customer_record_{suffix}"
            description = (
                "Synthetic database record for honeypot testing."
            )
            content = {
                "record_id": f"REC-{suffix.upper()}",
                "customer_name": (
                    f"Synthetic Customer {suffix[:6]}"
                ),
                "account_status": "TEST_ONLY",
            }

        # Every decoy explicitly carries the synthetic safety marker.
        content["synthetic_status"] = "INVALID_SYNTHETIC"

        return GeneratedDecoy(
            decoy_id=f"generated-{decoy_type}-{suffix}",
            actor_id=fingerprint.actor_id,
            decoy_type=decoy_type,
            name=name,
            description=description,
            content=content,
            generation_strategy=strategy,
            rationale=rationale,
        )


decoy_generator = BehaviorConditionedDecoyGenerator()