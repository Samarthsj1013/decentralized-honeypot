from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


BundleStrategy = Literal[
    "neutral_response",
    "file_decoy",
    "credential_decoy",
    "database_decoy",
    "expanded_decoy_path",
]

BundleRelationshipType = Literal[
    "has_identity",
    "has_database_record",
    "has_file",
    "exposed_as_api_resource",
]


class SyntheticEntity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: str
    employee_id: str
    synthetic_name: str
    department: str
    project_code: str
    service_identity: str
    synthetic_only: Literal[True] = True


class IdentityAsset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_id: str
    entity_id: str
    employee_id: str
    synthetic_name: str
    department: str
    project_code: str
    service_identity: str
    authentication_state: Literal["DISABLED_SYNTHETIC"] = "DISABLED_SYNTHETIC"
    synthetic_only: Literal[True] = True


class DatabaseRecordAsset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_id: str
    entity_id: str
    employee_id: str
    synthetic_name: str
    department: str
    project_code: str
    record_state: Literal["TEST_ONLY"] = "TEST_ONLY"
    synthetic_only: Literal[True] = True


class FileAsset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_id: str
    entity_id: str
    filename: str
    employee_id: str
    department: str
    project_code: str
    content: str
    synthetic_only: Literal[True] = True


class APIResourceAsset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_id: str
    entity_id: str
    method: Literal["GET"] = "GET"
    resource_path: str
    representation: dict[str, str]
    synthetic_only: Literal[True] = True


class BundleRelationship(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_asset_id: str
    relationship: BundleRelationshipType
    target_asset_id: str
    relationship_key: str = Field(min_length=1, max_length=200)


class SyntheticDecoyBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    bundle_id: str = Field(min_length=1, max_length=64)
    schema_version: int = Field(default=1, ge=1)
    actor_id: str = Field(min_length=1, max_length=64)
    scenario_id: str | None = Field(default=None, max_length=80)
    selected_strategy: BundleStrategy
    strategy_reason: str = Field(min_length=1, max_length=500)
    fingerprint_version: int = Field(ge=1)
    canonical_entities: list[SyntheticEntity]
    identities: list[IdentityAsset] = Field(default_factory=list)
    database_records: list[DatabaseRecordAsset] = Field(default_factory=list)
    files: list[FileAsset] = Field(default_factory=list)
    api_resources: list[APIResourceAsset] = Field(default_factory=list)
    relationships: list[BundleRelationship] = Field(default_factory=list)
    synthetic_only: Literal[True] = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BundleValidationIssue(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    message: str
    relationship_key: str | None = None
    affected_asset_ids: list[str] = Field(default_factory=list)


class BundleValidationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    bundle_id: str
    schema_version: int
    valid: bool
    issues: list[BundleValidationIssue] = Field(default_factory=list)


class BundleGenerationResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    bundle: SyntheticDecoyBundle
    validation: BundleValidationResult
    registered_decoy_ids: list[str]
    created: bool


class BundleConsistencyValidator:
    """Validate relationships between all modeled bundle assets."""

    SUPPORTED_SCHEMA_VERSIONS = {1}
    ASSET_RELATIONSHIPS = {
        "identities": "has_identity",
        "database_records": "has_database_record",
        "files": "has_file",
        "api_resources": "exposed_as_api_resource",
    }

    def validate(self, bundle: SyntheticDecoyBundle) -> BundleValidationResult:
        issues: list[BundleValidationIssue] = []

        def issue(
            code: str,
            message: str,
            ids: list[str] | None = None,
            relationship_key: str | None = None,
        ) -> None:
            issues.append(
                BundleValidationIssue(
                    code=code,
                    message=message,
                    affected_asset_ids=sorted(set(ids or [])),
                    relationship_key=relationship_key,
                )
            )

        if bundle.schema_version not in self.SUPPORTED_SCHEMA_VERSIONS:
            issue(
                "unsupported_schema_version",
                f"Unsupported bundle schema version {bundle.schema_version}.",
                [bundle.bundle_id],
            )
        if not bundle.canonical_entities:
            issue(
                "missing_canonical_entity",
                "A bundle must contain at least one canonical synthetic entity.",
                [bundle.bundle_id],
            )

        asset_groups = {
            "canonical_entities": bundle.canonical_entities,
            "identities": bundle.identities,
            "database_records": bundle.database_records,
            "files": bundle.files,
            "api_resources": bundle.api_resources,
        }
        identifiers: dict[str, list[str]] = {}
        for group_name, assets in asset_groups.items():
            for asset in assets:
                asset_id = (
                    asset.entity_id
                    if group_name == "canonical_entities"
                    else asset.asset_id
                )
                identifiers.setdefault(asset_id, []).append(group_name)

        for asset_id, groups in identifiers.items():
            if len(groups) > 1:
                issue(
                    "duplicate_asset_id",
                    f"Asset ID {asset_id} occurs in multiple collections.",
                    [asset_id],
                )

        entities = {entity.entity_id: entity for entity in bundle.canonical_entities}
        relationships = bundle.relationships
        expected_by_asset = {
            asset.asset_id: (asset.entity_id, relation)
            for collection, relation in self.ASSET_RELATIONSHIPS.items()
            for asset in getattr(bundle, collection)
        }
        relationship_keys: set[str] = set()
        relationship_tuples: set[tuple[str, str, str]] = set()
        for relationship in relationships:
            expected = expected_by_asset.get(relationship.target_asset_id)
            if expected is None or (
                relationship.source_asset_id != expected[0]
                or relationship.relationship != expected[1]
            ):
                issue(
                    "relationship_semantics_mismatch",
                    "Relationship source or type does not match the referenced asset.",
                    [relationship.source_asset_id, relationship.target_asset_id],
                    relationship.relationship_key,
                )
            key = relationship.relationship_key
            if key in relationship_keys:
                issue(
                    "duplicate_relationship_key",
                    f"Relationship key {key} is duplicated.",
                    [relationship.source_asset_id, relationship.target_asset_id],
                    key,
                )
            relationship_keys.add(key)
            relationship_tuple = (
                relationship.source_asset_id,
                relationship.relationship,
                relationship.target_asset_id,
            )
            if relationship_tuple in relationship_tuples:
                issue(
                    "duplicate_relationship",
                    "The same relationship is declared more than once.",
                    [relationship.source_asset_id, relationship.target_asset_id],
                    key,
                )
            relationship_tuples.add(relationship_tuple)

        all_ids = set(identifiers)
        for relationship in relationships:
            missing = [
                asset_id
                for asset_id in (
                    relationship.source_asset_id,
                    relationship.target_asset_id,
                )
                if asset_id not in all_ids
            ]
            if missing:
                issue(
                    "dangling_relationship",
                    "Relationship references an asset ID that does not exist.",
                    [relationship.source_asset_id, relationship.target_asset_id],
                    relationship.relationship_key,
                )

        for collection_name, expected_relationship in self.ASSET_RELATIONSHIPS.items():
            for asset in getattr(bundle, collection_name):
                entity_id = asset.entity_id
                canonical = entities.get(entity_id)
                if canonical is None:
                    issue(
                        "dangling_entity_reference",
                        f"Asset references missing canonical entity {entity_id}.",
                        [asset.asset_id, entity_id],
                    )
                    continue

                expected_relationship_tuple = (
                    entity_id,
                    expected_relationship,
                    asset.asset_id,
                )
                if expected_relationship_tuple not in relationship_tuples:
                    issue(
                        "missing_asset_relationship",
                        f"Canonical entity has no {expected_relationship} link to this asset.",
                        [entity_id, asset.asset_id],
                        "|".join(expected_relationship_tuple),
                    )

                comparable_fields = (
                    () if isinstance(asset, APIResourceAsset)
                    else ("employee_id", "department", "project_code")
                )
                for field_name in comparable_fields:
                    if getattr(asset, field_name, None) != getattr(
                        canonical, field_name
                    ):
                        issue(
                            "canonical_value_mismatch",
                            f"{field_name} does not match canonical entity {entity_id}.",
                            [entity_id, asset.asset_id],
                            "|".join(expected_relationship_tuple),
                        )
                if isinstance(asset, IdentityAsset) and (
                    asset.synthetic_name != canonical.synthetic_name
                    or asset.service_identity != canonical.service_identity
                ):
                    issue(
                        "identity_reference_mismatch",
                        "Identity asset values do not match their canonical entity.",
                        [entity_id, asset.asset_id],
                        "|".join(expected_relationship_tuple),
                    )
                if isinstance(asset, FileAsset):
                    if any(
                        line not in asset.content.splitlines()
                        for line in (
                            f"employee_id: {canonical.employee_id}",
                            f"department: {canonical.department}",
                            f"project_code: {canonical.project_code}",
                        )
                    ):
                        issue(
                            "file_content_mismatch",
                            "File content omits or disagrees with canonical entity values.",
                            [entity_id, asset.asset_id],
                            "|".join(expected_relationship_tuple),
                        )
                if isinstance(asset, APIResourceAsset):
                    expected_values = {
                        "employee_id": canonical.employee_id,
                        "department": canonical.department,
                        "project_code": canonical.project_code,
                        "service_identity": canonical.service_identity,
                    }
                    if any(
                        asset.representation.get(key) != value
                        for key, value in expected_values.items()
                    ):
                        issue(
                            "api_representation_mismatch",
                            "API representation does not match its canonical entity.",
                            [entity_id, asset.asset_id],
                            "|".join(expected_relationship_tuple),
                        )

        identity_by_entity = {asset.entity_id: asset for asset in bundle.identities}
        records_by_entity = {
            asset.entity_id: asset for asset in bundle.database_records
        }
        for entity_id in identity_by_entity.keys() & records_by_entity.keys():
            identity = identity_by_entity[entity_id]
            record = records_by_entity[entity_id]
            if (
                identity.employee_id != record.employee_id
                or identity.project_code != record.project_code
            ):
                issue(
                    "identity_database_link_mismatch",
                    "Identity and database record disagree on employee or project identifiers.",
                    [identity.asset_id, record.asset_id],
                    f"{identity.asset_id}|identity_database_link|{record.asset_id}",
                )

        return BundleValidationResult(
            bundle_id=bundle.bundle_id,
            schema_version=bundle.schema_version,
            valid=not issues,
            issues=issues,
        )
