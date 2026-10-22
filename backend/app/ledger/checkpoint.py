
import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel

from app.ledger.service import EventLedger, event_ledger


class SignedCheckpoint(BaseModel):
    """A digitally signed snapshot of a ledger's current head."""

    sequence: int
    head_hash: str
    signed_at: datetime
    signature: str
    algorithm: str = "Ed25519"


class CheckpointVerification(BaseModel):
    """Outcome of verifying a signed checkpoint."""

    valid: bool
    signature_valid: bool
    ledger_matches: bool
    ledger_integrity_valid: bool
    message: str
    first_invalid_sequence: int | None = None


class LedgerCheckpointService:
    """
    Creates and verifies signed checkpoints for the local ledger.

    The signing key is generated once and stored locally.
    Protect the private key: anyone who obtains it can sign checkpoints.
    """

    def __init__(
        self,
        ledger: EventLedger,
        private_key_path: str | Path,
        public_key_path: str | Path,
    ) -> None:
        self._ledger = ledger
        self._private_key_path = Path(private_key_path)
        self._public_key_path = Path(public_key_path)

        self._private_key_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self._public_key_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._private_key = self._load_or_create_private_key()
        self._public_key = self._private_key.public_key()

    def _load_or_create_private_key(self) -> Ed25519PrivateKey:
        if self._private_key_path.exists():
            key = serialization.load_pem_private_key(
                self._private_key_path.read_bytes(),
                password=None,
            )

            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(
                    "The configured private key is not an Ed25519 key."
                )

            public_pem = self._public_key_pem(key.public_key())

            if self._public_key_path.exists():
                existing_public = self._public_key_path.read_bytes()
                if existing_public != public_pem:
                    raise ValueError(
                        "Public key does not match the private key."
                    )
            else:
                self._public_key_path.write_bytes(public_pem)

            return key

        if self._public_key_path.exists():
            raise ValueError(
                "Public key exists but private key is missing. "
                "Refusing to generate a replacement key."
            )

        key = Ed25519PrivateKey.generate()

        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        self._private_key_path.write_bytes(private_pem)
        self._public_key_path.write_bytes(
            self._public_key_pem(key.public_key())
        )

        return key

    @staticmethod
    def _public_key_pem(key: Ed25519PublicKey) -> bytes:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def _canonical_payload(
        sequence: int,
        head_hash: str,
        signed_at: datetime,
    ) -> bytes:
        payload = {
            "algorithm": "Ed25519",
            "sequence": sequence,
            "head_hash": head_hash,
            "signed_at": signed_at.isoformat(),
        }

        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def create_checkpoint(self) -> SignedCheckpoint:
        entries = self._ledger.list_entries()

        if entries:
            sequence = entries[-1].sequence
            head_hash = entries[-1].entry_hash
        else:
            sequence = 0
            head_hash = "0" * 64

        signed_at = datetime.now(timezone.utc)
        payload = self._canonical_payload(
            sequence,
            head_hash,
            signed_at,
        )

        signature = self._private_key.sign(payload)

        return SignedCheckpoint(
            sequence=sequence,
            head_hash=head_hash,
            signed_at=signed_at,
            signature=base64.b64encode(signature).decode("ascii"),
        )

    def verify_checkpoint(
        self,
        checkpoint: SignedCheckpoint,
    ) -> CheckpointVerification:
        payload = self._canonical_payload(
            checkpoint.sequence,
            checkpoint.head_hash,
            checkpoint.signed_at,
        )

        try:
            signature = base64.b64decode(
                checkpoint.signature,
                validate=True,
            )
            self._public_key.verify(signature, payload)
            signature_valid = True
        except (InvalidSignature, ValueError, TypeError):
            signature_valid = False

        integrity = self._ledger.verify_persisted_chain()
        entries = self._ledger.list_entries()

        if entries:
            current_sequence = entries[-1].sequence
            current_head_hash = entries[-1].entry_hash
        else:
            current_sequence = 0
            current_head_hash = "0" * 64

        ledger_matches = (
            checkpoint.sequence == current_sequence
            and checkpoint.head_hash == current_head_hash
        )

        valid = (
            signature_valid
            and ledger_matches
            and integrity.valid
        )

        if not signature_valid:
            message = "Checkpoint signature is invalid."
        elif not integrity.valid:
            if integrity.first_invalid_sequence is None:
                message = (
                    "Ledger integrity verification failed: "
                    f"{integrity.message}"
                )
            else:
                message = (
                    "Ledger integrity verification failed at sequence "
                    f"{integrity.first_invalid_sequence}: {integrity.message}"
                )
        elif not ledger_matches:
            message = "Checkpoint does not match the current ledger head."
        else:
            message = "Checkpoint signature and ledger head are valid."

        return CheckpointVerification(
            valid=valid,
            signature_valid=signature_valid,
            ledger_matches=ledger_matches,
            ledger_integrity_valid=integrity.valid,
            first_invalid_sequence=integrity.first_invalid_sequence,
            message=message,
        )


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIRECTORY = PROJECT_ROOT / "backend" / "data"

checkpoint_service = LedgerCheckpointService(
    ledger=event_ledger,
    private_key_path=DATA_DIRECTORY / "ledger_signing_private.pem",
    public_key_path=DATA_DIRECTORY / "ledger_signing_public.pem",
)
