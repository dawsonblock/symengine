"""Anchor chain: external head custody and divergence detection."""
import tempfile
import unittest
from pathlib import Path

from sis.v3.audit import AnchorChain, AnchorError
from sis.v3.contracts import ObservationEventV1, canonical_digest
from sis.v3.episode_store import EpisodeStore


def _event(seq, prior=None, episode="ep-1"):
    payload = {"n": seq}
    return ObservationEventV1(
        schema_version=1, event_id=f"e{seq}", episode_id=episode,
        attempt_id="a", seq=seq, event_type="read",
        timestamp="2026-01-01T00:00:00Z", actor="agent",
        inputs_digest=None, outputs_digest=None, artifact_refs=(),
        prior_event_digest=prior, idempotency_key=f"e{seq}",
        payload_digest=canonical_digest("event_payload", 1, payload),
        payload=payload,
    )


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = EpisodeStore(self.root / "evidence")
        self.chain = AnchorChain(self.root / "anchors")

    def test_anchor_and_verify_clean(self):
        self.store.append_event(_event(0))
        entry = self.chain.anchor_episode(self.store, "ep-1")
        report = self.chain.verify_all(self.store)
        self.assertTrue(report["ok"], report)
        self.assertEqual(entry["event_count"], 1)

    def test_append_after_anchor_is_reported_growth(self):
        e0 = self.store.append_event(_event(0))
        self.chain.anchor_episode(self.store, "ep-1")
        self.store.append_event(_event(1, prior=e0.digest))
        report = self.chain.verify_all(self.store)
        self.assertFalse(report["ok"])
        self.assertEqual(report["divergences"][0]["kind"], "grew_after_anchor")

    def test_corrupt_episode_flagged(self):
        e0 = self.store.append_event(_event(0))
        self.chain.anchor_episode(self.store, "ep-1")
        log = self.root / "evidence" / "episodes" / "ep-1.jsonl"
        log.write_bytes(log.read_bytes() + b'{"forged":1}\n')
        report = self.chain.verify_all(self.store)
        self.assertFalse(report["ok"])
        self.assertEqual(report["divergences"][0]["kind"], "corrupt")

    def test_corrupt_anchor_log_rejected(self):
        self.store.append_event(_event(0))
        self.chain.anchor_episode(self.store, "ep-1")
        log = self.root / "anchors" / "anchors.jsonl"
        log.write_bytes(log.read_bytes().replace(b'"ep-1"', b'"ep-9"', 1))
        # episode_id itself is data; chain seq/shape still valid -> loads fine,
        # but head for ep-1 is no longer anchored.
        fresh = AnchorChain(self.root / "anchors")
        report = fresh.verify_all(self.store)
        self.assertFalse(report["ok"])

    def test_chain_persists_across_reopen(self):
        self.store.append_event(_event(0))
        self.chain.anchor_episode(self.store, "ep-1")
        fresh = AnchorChain(self.root / "anchors")
        self.assertEqual(len(fresh.entries()), 1)
        self.assertTrue(fresh.verify_all(self.store)["ok"])

    def test_cannot_anchor_corrupt_episode(self):
        log_dir = self.root / "evidence" / "episodes"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "bad.jsonl").write_bytes(b"garbage\n")
        with self.assertRaises(AnchorError):
            self.chain.anchor_episode(self.store, "bad")


if __name__ == "__main__":
    unittest.main()
