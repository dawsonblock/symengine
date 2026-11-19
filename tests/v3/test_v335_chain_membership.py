"""V335-03: explicit chain membership for trusted memory reads.

``_chain_state`` proves a store-wide invariant: the chain covers exactly
the experience rows present. That is not evidence that the record a
caller is about to trust owns a chain entry, and it is evaluated at a
different instant from the row read. These tests pin the repaired
contract: trust requires the exact record to be a chain member, and a row
that appears between the invariant check and the row read is rejected.
"""
from __future__ import annotations

import unittest

from sis.v3.memory import MemoryError, MemoryStore

from tests.v3.test_v334_memory_trust import MemoryFixture, _v1_record


class MembershipTrustTests(MemoryFixture):
    """Trust is membership-bound, not merely store-wide consistent."""

    def test_unstored_record_is_not_trusted(self):
        store = self.store()
        self.addCleanup(store.close)
        record = self.record()
        # The store-wide invariant holds: an empty chain covers the
        # empty table. The record was never ingested, so it is not a
        # member and cannot be trusted on its signature alone.
        self.assertTrue(store.verify_chain())
        self.assertEqual(
            store.trust_status(record),
            "untrusted:experience_unchained:exp-1")
        self.assertFalse(store.is_trusted(record))

    def test_ingested_record_becomes_trusted_member(self):
        store = self.store()
        self.addCleanup(store.close)
        record = self.record()
        store.ingest(record)
        self.assertEqual(store.trust_status(record), "trusted")
        self.assertTrue(store.is_trusted(record))

    def test_by_outcome_rejects_row_added_after_the_chain_check(self):
        record = self.record(experience_id="exp-2", episode_id="ep-2")

        class _InterleavedStore(MemoryStore):
            """Simulate a writer landing a row between check and read."""

            armed = False
            injected = False

            def _require_chain(self):
                super()._require_chain()
                if not self.armed or self.injected:
                    return
                self.injected = True
                self._conn().execute(
                    "INSERT INTO experience"
                    " (experience_id, episode_id, task_fingerprint,"
                    "  repository_registry_id, record_digest, record_json,"
                    "  outcome, captured_at) VALUES (?,?,?,?,?,?,?,?)",
                    (record.experience_id, record.episode_id,
                     record.task_fingerprint, record.repository_registry_id,
                     record.digest,
                     record.canonical_bytes().decode("utf-8"),
                     record.outcome, record.captured_at))

        store = _InterleavedStore(
            self.root / "db" / "race.db",
            trusted_signer_keys={"exp-key-1": self.record_public.hex()},
            chain_key=(self.chain_seed, "chain-key-1"),
            profile=None, witness=self.witness(), verifier=self.verifier)
        self.addCleanup(store.close)
        store.ingest(self.record())
        # The store-wide invariant held when the check ran; the unchained
        # row appears immediately after it, before the row query.
        store.armed = True
        with self.assertRaisesRegex(MemoryError, "experience_unchained:exp-2"):
            store.by_outcome(record.outcome)

    def test_development_reads_do_not_require_chain_membership(self):
        store = MemoryStore(self.root / "db" / "dev.db")
        self.addCleanup(store.close)
        store.ingest(_v1_record())
        store._conn().execute("DELETE FROM memory_chain")
        self.assertEqual(store.get("exp-v1").experience_id, "exp-v1")
        self.assertEqual(
            [r.experience_id for r in store.by_outcome("fail")], ["exp-v1"])


if __name__ == "__main__":
    unittest.main()
