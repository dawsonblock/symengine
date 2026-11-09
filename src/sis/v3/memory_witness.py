"""External memory-chain witness (SIS v3.3.4, Phase 3.2).

The memory chain proves internal consistency: every stored record digest
appears in order, and a mid-history edit or deletion breaks the chain.
It cannot prove that the newest entries still exist, because a writer
who controls the database can restore an older snapshot whose chain
verifies perfectly.

A witness closes that hole. It records the last observed chain position
in a file signed under a separate custodian key, stored outside the
memory database's directory. A restored snapshot then presents an older
sequence than the witness and is rejected as a rewind.

The witness is append-only and every record commits to the previous
witness digest, so deleting or rewriting an interior witness record is
also detectable. It is not a substitute for an independent host: a
principal that controls both the database and the witness key can still
forge a consistent pair. Deployments must keep the witness key and path
under a different authority from the memory database.
"""
from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import signatures
from .contracts import ContractError, canonical_digest, canonical_json, loads_json
from ..errors import InvalidInput
from ..vault_storage import (
    assert_private_acl,
    create_private_file,
    ensure_private_directory,
)

_WITNESS_DOMAIN = b"sis-v3:memory_witness:1\0"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_SIGNATURE = re.compile(r"[0-9a-f]{128}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}")

_FIELDS = frozenset({
    "schema_version", "sequence", "memory_head_digest",
    "previous_witness_digest", "timestamp", "signer_key_id", "signature",
})


class WitnessError(RuntimeError):
    """The witness cannot be read, verified, advanced, or reconciled."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ContractError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_private(path: Path, label: str) -> None:
    """Fail closed as a witness error, not a generic input error."""
    try:
        assert_private_acl(path, label)
    except InvalidInput as exc:
        raise WitnessError("witness_insecure", str(exc)) from exc


@dataclass(frozen=True)
class WitnessRecord:
    """One signed observation of the memory chain head."""

    schema_version: int
    sequence: int
    memory_head_digest: str
    previous_witness_digest: str | None
    timestamp: str
    signer_key_id: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "memory_head_digest": self.memory_head_digest,
            "previous_witness_digest": self.previous_witness_digest,
            "timestamp": self.timestamp,
            "signer_key_id": self.signer_key_id,
            "signature": self.signature,
        }

    def unsigned(self) -> dict:
        body = self.to_dict()
        body.pop("signature")
        return body

    @property
    def digest(self) -> str:
        return canonical_digest("memory_witness", 1, self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping) -> "WitnessRecord":
        if not isinstance(value, Mapping) or set(value) != _FIELDS:
            raise ContractError("witness record fields differ from schema")
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ContractError("witness schema_version must be integer 1")
        sequence = value["sequence"]
        if type(sequence) is not int or sequence < 1:
            raise ContractError("witness sequence must be a positive integer")
        _require_digest(value["memory_head_digest"], "memory_head_digest")
        previous = value["previous_witness_digest"]
        if previous is not None:
            _require_digest(previous, "previous_witness_digest")
        for name in ("timestamp", "signer_key_id"):
            item = value[name]
            if not isinstance(item, str) or not item:
                raise ContractError(f"witness {name} must be a nonempty string")
        signature = value["signature"]
        if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
            raise ContractError("witness signature must be a 64-byte lowercase hex value")
        return cls(
            schema_version=1,
            sequence=sequence,
            memory_head_digest=value["memory_head_digest"],
            previous_witness_digest=previous,
            timestamp=value["timestamp"],
            signer_key_id=value["signer_key_id"],
            signature=signature,
        )


class MemoryWitness:
    """Append-only, signed, separately stored memory-chain witness."""

    def __init__(self, path: str | Path, *, seed: bytes, key_id: str) -> None:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("witness seed must be 32 bytes")
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise ContractError("witness key_id must be a valid identifier")
        self.path = Path(path)
        self._seed = bytes(seed)
        self._key_id = key_id
        self._public = signatures.public_key(self._seed)
        self._cache: tuple[tuple[int, int], tuple[WitnessRecord, ...]] | None = None
        ensure_private_directory(self.path.parent, "memory witness directory")

    def records(self) -> tuple[WitnessRecord, ...]:
        """Read, authenticate, and chain-check every witness record.

        The verified result is cached against the file's size and
        modification time, so repeated production reads do not re-verify
        the whole history. Any append or external edit changes the
        fingerprint and forces a full re-check.
        """
        if not self.path.exists():
            return ()
        _require_private(self.path, "memory witness")
        info = self.path.stat()
        fingerprint = (info.st_size, info.st_mtime_ns)
        if self._cache is not None and self._cache[0] == fingerprint:
            return self._cache[1]
        parsed: list[WitnessRecord] = []
        for position, raw in enumerate(self.path.read_bytes().splitlines()):
            try:
                record = WitnessRecord.from_dict(loads_json(raw))
            except ContractError as exc:
                raise WitnessError(
                    "witness_corrupt", f"line {position}: {exc}") from exc
            if record.signer_key_id != self._key_id:
                raise WitnessError(
                    "witness_untrusted_signer", f"line {position}")
            if not signatures.verify(
                    bytes.fromhex(record.signature),
                    _WITNESS_DOMAIN + canonical_json(record.unsigned()),
                    self._public):
                raise WitnessError(
                    "witness_signature_invalid", f"line {position}")
            expected_previous = parsed[-1].digest if parsed else None
            if record.previous_witness_digest != expected_previous:
                raise WitnessError(
                    "witness_chain_broken", f"line {position}")
            if parsed and record.sequence <= parsed[-1].sequence:
                raise WitnessError(
                    "witness_sequence_regressed", f"line {position}")
            parsed.append(record)
        self._cache = (fingerprint, tuple(parsed))
        return self._cache[1]

    def latest(self) -> WitnessRecord | None:
        records = self.records()
        return records[-1] if records else None

    def advance(self, *, sequence: int,
                memory_head_digest: str) -> WitnessRecord:
        """Append a signed observation of a newer chain position."""
        if type(sequence) is not int or sequence < 1:
            raise ContractError("witness sequence must be a positive integer")
        _require_digest(memory_head_digest, "memory_head_digest")
        before_size = self.path.stat().st_size if self.path.exists() else 0
        existing = self.records()
        latest = existing[-1] if existing else None
        if latest is not None and sequence <= latest.sequence:
            raise WitnessError(
                "witness_sequence_not_advancing",
                f"{sequence} <= {latest.sequence}")
        record = self._sign(
            sequence=sequence,
            memory_head_digest=memory_head_digest,
            previous=latest.digest if latest is not None else None,
        )
        payload = canonical_json(record.to_dict()) + b"\n"
        if self.path.exists():
            _require_private(self.path, "memory witness")
            with open(self.path, "ab") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        else:
            try:
                create_private_file(self.path, payload, "memory witness")
            except FileExistsError:
                # A concurrent custodian won the create; append through
                # the existing private file instead of replacing it.
                _require_private(self.path, "memory witness")
                with open(self.path, "ab") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            except InvalidInput as exc:
                raise WitnessError("witness_insecure", str(exc)) from exc
        info = self.path.stat()
        if info.st_size == before_size + len(payload):
            self._cache = ((info.st_size, info.st_mtime_ns), existing + (record,))
        else:
            # Another writer appended between our read and our write; the
            # cached prefix no longer describes the file, so re-verify.
            self._cache = None
        return record

    def verify_against(self, *, sequence: int,
                       memory_head_digest: str | None) -> None:
        """Require the store's position to match the newest witness."""
        latest = self.latest()
        if latest is None:
            if sequence == 0 and memory_head_digest is None:
                return
            raise WitnessError(
                "witness_missing",
                "the store holds entries but no witness exists")
        if latest.sequence == sequence and latest.memory_head_digest == memory_head_digest:
            return
        if latest.sequence > sequence:
            raise WitnessError(
                "memory_rollback_detected",
                f"store is at sequence {sequence}, witness at {latest.sequence}")
        if latest.sequence < sequence:
            raise WitnessError(
                "memory_witness_stale",
                f"store is at sequence {sequence}, witness at {latest.sequence}")
        raise WitnessError(
            "memory_head_mismatch",
            "the store and witness disagree at the same sequence")

    def _sign(self, *, sequence: int, memory_head_digest: str,
              previous: str | None) -> WitnessRecord:
        unsigned = {
            "schema_version": 1,
            "sequence": sequence,
            "memory_head_digest": memory_head_digest,
            "previous_witness_digest": previous,
            "timestamp": _utcnow(),
            "signer_key_id": self._key_id,
        }
        signature = signatures.sign(
            self._seed, _WITNESS_DOMAIN + canonical_json(unsigned)).hex()
        return WitnessRecord.from_dict({**unsigned, "signature": signature})
