"""Persistent, atomic once-only consumption of signed outcome envelopes.

Verification and nonce admission are a single serialized SQLite transaction.
Do not confuse a legitimate read-only signature verification with a receipt
being admitted for promotion for the first time.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .contracts import OutcomeEnvelopeV2
from .outcome_v2 import TrustedKeyRegistry, verify_envelope


class NonceAlreadyConsumed(RuntimeError):
    pass


class EnvelopeAdmissionError(RuntimeError):
    pass


class OutcomeNonceStore:
    def __init__(self, database: str | Path):
        self.database = str(database)
        Path(database).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database, timeout=15) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS accepted_envelopes ("
                       "signer TEXT NOT NULL, nonce TEXT NOT NULL, digest TEXT NOT NULL, "
                       "PRIMARY KEY (signer, nonce))")

    def verify_and_consume(self, envelope: OutcomeEnvelopeV2, registry: TrustedKeyRegistry, *,
                           revoked_keys=frozenset(), at_time=None) -> str:
        if not verify_envelope(envelope, registry, revoked_keys=revoked_keys, at_time=at_time):
            raise EnvelopeAdmissionError("signature_or_policy_invalid")
        with sqlite3.connect(self.database, isolation_level=None, timeout=15) as db:
            db.execute("BEGIN IMMEDIATE")
            # Reverify inside the write transaction to minimize expiry races.
            if not verify_envelope(envelope, registry, revoked_keys=revoked_keys, at_time=at_time):
                db.execute("ROLLBACK")
                raise EnvelopeAdmissionError("envelope_expired_during_admission")
            try:
                db.execute("INSERT INTO accepted_envelopes (signer, nonce, digest) VALUES (?, ?, ?)",
                           (envelope.signer_key_id, envelope.nonce, envelope.digest))
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise NonceAlreadyConsumed("nonce_replayed") from exc
            db.execute("COMMIT")
        return envelope.digest
