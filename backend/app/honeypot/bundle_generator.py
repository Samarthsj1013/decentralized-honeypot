"""Deterministic generator for internally consistent synthetic decoy bundles."""

import hashlib
import json

from app.honeypot.bundles import (
    APIResourceAsset,
    BundleRelationship,
    DatabaseRecordAsset,
    FileAsset,
    IdentityAsset,
    SyntheticDecoyBundle,
    SyntheticEntity,
)
from app.honeypot.generator import GeneratedDecoy
from app.intelligence.service import BehavioralFingerprint


class BehaviorConditionedBundleGenerator:
    def generate_bundle(
        self,
        fingerprint: BehavioralFingerprint,
        selected_strategy: str,
        strategy_reason: str,
        scenario_id: str | None = None,
    ) -> SyntheticDecoyBundle:
        source = {
            "actor": fingerprint.actor_id,
            "scenario": scenario_id,
            "strategy": selected_strategy,
            "version": fingerprint.fingerprint_version,
            "actions": fingerprint.action_sequence,
            "decoys": fingerprint.decoy_types_accessed,
            "credentials": fingerprint.credential_probing,
            "database": fingerprint.database_probing,
            "files": fingerprint.file_probing,
            "repeated": fingerprint.repeated_access,
            "event_count": fingerprint.event_count,
        }
        digest = hashlib.sha256(
            json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:24]
        bundle_id = f"bundle-{digest}"
        suffix = digest[:10].upper()
        entity_id = f"{bundle_id}-entity"
        entity = SyntheticEntity(
            entity_id=entity_id,
            employee_id=f"EMP-{suffix}",
            synthetic_name=f"Synthetic Employee {suffix}",
            department="Research Sandbox",
            project_code=f"LAB-{suffix}",
            service_identity=f"synthetic_service_{suffix.lower()}",
        )

        include_identity = selected_strategy in {
            "credential_decoy", "expanded_decoy_path"
        }
        include_database = selected_strategy in {
            "database_decoy", "expanded_decoy_path"
        }
        include_file = selected_strategy in {
            "file_decoy", "expanded_decoy_path"
        }
        if fingerprint.file_probing:
            include_file = True
        if not (include_identity or include_database or include_file):
            include_file = True
        include_api = include_identity or include_database

        identities = [IdentityAsset(
            asset_id=f"{bundle_id}-identity", entity_id=entity_id,
            employee_id=entity.employee_id, synthetic_name=entity.synthetic_name,
            department=entity.department, project_code=entity.project_code,
            service_identity=entity.service_identity,
        )] if include_identity else []
        records = [DatabaseRecordAsset(
            asset_id=f"{bundle_id}-record", entity_id=entity_id,
            employee_id=entity.employee_id, synthetic_name=entity.synthetic_name,
            department=entity.department, project_code=entity.project_code,
        )] if include_database else []
        files = [FileAsset(
            asset_id=f"{bundle_id}-file", entity_id=entity_id,
            filename=f"{suffix.lower()}_profile.txt", employee_id=entity.employee_id,
            department=entity.department, project_code=entity.project_code,
            content=(
                "SYNTHETIC TEST DATA ONLY\n"
                f"employee_id: {entity.employee_id}\n"
                f"department: {entity.department}\n"
                f"project_code: {entity.project_code}\n"
            ),
        )] if include_file else []
        api_resources = [APIResourceAsset(
            asset_id=f"{bundle_id}-api", entity_id=entity_id,
            resource_path=f"/synthetic/api/v1/entities/{suffix.lower()}",
            representation={
                "employee_id": entity.employee_id,
                "synthetic_name": entity.synthetic_name,
                "department": entity.department,
                "project_code": entity.project_code,
                "service_identity": entity.service_identity,
                "state": "TEST_ONLY",
            },
        )] if include_api else []

        assets = [
            (identities, "has_identity"),
            (records, "has_database_record"),
            (files, "has_file"),
            (api_resources, "exposed_as_api_resource"),
        ]
        relationships = []
        for group, relationship in assets:
            for asset in group:
                relationships.append(BundleRelationship(
                    source_asset_id=entity_id,
                    relationship=relationship,
                    target_asset_id=asset.asset_id,
                    relationship_key=f"{entity_id}|{relationship}|{asset.asset_id}",
                ))

        return SyntheticDecoyBundle(
            bundle_id=bundle_id,
            actor_id=fingerprint.actor_id,
            scenario_id=scenario_id,
            selected_strategy=selected_strategy,
            strategy_reason=strategy_reason,
            fingerprint_version=fingerprint.fingerprint_version,
            canonical_entities=[entity], identities=identities,
            database_records=records, files=files, api_resources=api_resources,
            relationships=relationships,
        )

    @staticmethod
    def to_generated_decoys(bundle: SyntheticDecoyBundle) -> list[GeneratedDecoy]:
        rationale = [bundle.strategy_reason, f"Synthetic bundle {bundle.bundle_id}"]
        common = {
            "actor_id": bundle.actor_id,
            "generation_strategy": f"bundle:{bundle.selected_strategy}",
            "rationale": rationale,
            "fingerprint_version": bundle.fingerprint_version,
            "generation_parameters": {"bundle_id": bundle.bundle_id},
            "synthetic_only": True,
        }
        decoys: list[GeneratedDecoy] = []
        for asset in bundle.identities:
            decoys.append(GeneratedDecoy(
                **common, decoy_id=asset.asset_id, decoy_type="credential",
                name=f"Synthetic identity {asset.employee_id}",
                description="Disabled synthetic identity for simulation only.",
                content={"employee_id": asset.employee_id,
                         "name": asset.synthetic_name,
                         "department": asset.department,
                         "project_code": asset.project_code,
                         "service_identity": asset.service_identity,
                         "authentication_state": asset.authentication_state},
            ))
        for asset in bundle.database_records:
            decoys.append(GeneratedDecoy(
                **common, decoy_id=asset.asset_id, decoy_type="database_record",
                name=f"Synthetic record {asset.employee_id}",
                description="Test-only synthetic database record.",
                content={"employee_id": asset.employee_id,
                         "name": asset.synthetic_name,
                         "department": asset.department,
                         "project_code": asset.project_code,
                         "record_state": asset.record_state},
            ))
        for asset in bundle.files:
            decoys.append(GeneratedDecoy(
                **common, decoy_id=asset.asset_id, decoy_type="file",
                name=asset.filename, description="Synthetic profile file.",
                content={"employee_id": asset.employee_id,
                         "department": asset.department,
                         "project_code": asset.project_code,
                         "content": asset.content},
            ))
        return decoys
