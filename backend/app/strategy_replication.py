"""In-process multi-organization strategy replication demonstration.

Each node owns an independent sharing store and signing key. Records cross the
boundary as JSON-compatible payloads and are verified by the receiver's
explicit trust map. This module provides no network transport or consensus.
"""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from app.intelligence.fingerprint_schema import ShareableFingerprintExportV1
from app.strategy_sharing import (
    ImportResponse,
    StrategyShareRecord,
    StrategySharingService,
    StrategySharingStorage,
)


class SimulatedOrganizationNode:
    """A local node with its own key pair, trust map, and SQLite store.

    The constructor requires the node's public key to be explicitly present
    in its trust map, matching the publisher/key mapping used for signing.
    Callers pass only public keys for peers; private keys stay with their node.
    """

    def __init__(
        self,
        organization_id: str,
        key_id: str,
        database_path: str | Path,
        trusted_keys: dict[str, tuple[str, Ed25519PublicKey]],
        private_key: Ed25519PrivateKey,
        evaluation_runner=None,
    ) -> None:
        if not organization_id or not key_id:
            raise ValueError("Simulated organization and key IDs are required")
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Node signing key must be Ed25519")

        own_trust = trusted_keys.get(key_id)
        if own_trust is None or own_trust[0] != organization_id:
            raise ValueError("Node signing key must be explicitly trusted for its organization")
        if not isinstance(own_trust[1], Ed25519PublicKey):
            raise ValueError("Trusted node key must be Ed25519")
        own_public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        trusted_public_bytes = own_trust[1].public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if own_public_bytes != trusted_public_bytes:
            raise ValueError("Node private key does not match its explicitly trusted public key")

        self.organization_id = organization_id
        self.key_id = key_id
        self.database_path = Path(database_path)
        self._private_key = private_key
        self._service = StrategySharingService(
            StrategySharingStorage(self.database_path),
            trusted_keys,
            signer=private_key,
            signer_organization=organization_id,
            evaluation_runner=evaluation_runner,
        )

    @property
    def public_key(self) -> Ed25519PublicKey:
        """Return only this node's public key for explicit peer provisioning."""
        return self._private_key.public_key()

    def export(
        self,
        strategy: str,
        fingerprint: ShareableFingerprintExportV1,
        bundle,
    ) -> StrategyShareRecord:
        return self._service.create_record(
            self.organization_id, self.key_id, strategy, fingerprint, bundle
        )

    @staticmethod
    def transfer_payload(record: StrategyShareRecord) -> dict:
        """Make the explicit JSON-compatible transport payload."""
        return record.model_dump(mode="json")

    def receive(self, payload: dict) -> ImportResponse:
        return self._service.import_record(payload)

    def evaluate(self, record_id: str) -> ImportResponse:
        return self._service.evaluate(record_id)

    def approve(self, record_id: str) -> ImportResponse:
        """Record local approval after the existing receiver-side checks."""
        return self._service.activate(record_id)

    def status(self, record_id: str) -> ImportResponse:
        return self._service.get(record_id)

    def stored_record(self, record_id: str) -> StrategyShareRecord | None:
        """Return the validated record for local inspection, never its DB row."""
        row = self._service.storage.get(record_id)
        if row is None:
            return None
        return StrategyShareRecord.model_validate_json(row["record_json"])
