import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError, ObservationEventV1, canonical_digest, canonical_json
from sis.v3.episode_store import (
    ConflictError,
    EpisodeStore,
    EpisodeStoreError,
    IntegrityError,
)


def make_event(episode, seq, prior, *, event_id=None, key=None, payload=None, artifacts=()):
    body = payload or {"note": f"event-{seq}"}
    return ObservationEventV1(
        schema_version=1,
        event_id=event_id or f"ev-{episode}-{seq}",
        episode_id=episode,
        attempt_id="attempt-1",
        seq=seq,
        event_type="tool_result",
        timestamp="2026-10-23T12:00:00Z",
        actor="agent",
        inputs_digest=None,
        outputs_digest=None,
        artifact_refs=tuple(artifacts),
        prior_event_digest=prior,
        idempotency_key=key or f"key-{episode}-{seq}",
        payload_digest=canonical_digest("event_payload", 1, body),
        payload=body,
    )


class EpisodeStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = EpisodeStore(Path(self.temp.name) / "evidence")

    def chain(self, episode, count):
        prior = None
        events = []
        for seq in range(count):
            event = make_event(episode, seq, prior)
            self.store.append_event(event)
            prior = event.digest
            events.append(event)
        return events

    def test_append_replay_and_head_chain(self):
        events = self.chain("ep-a", 3)
        replayed = self.store.events("ep-a")
        self.assertEqual([e.event_id for e in replayed], [e.event_id for e in events])
        self.assertEqual(self.store.head_digest("ep-a"), events[-1].digest)
        report = self.store.verify_episode("ep-a")
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["events"], 3)

    def test_retry_on_stable_event_is_idempotent(self):
        event = make_event("ep-b", 0, None)
        first = self.store.append_event(event)
        again = self.store.append_event(event)
        self.assertEqual(first.digest, again.digest)
        self.assertEqual(self.store.verify_episode("ep-b")["events"], 1)

    def test_conflicting_identity_seq_and_chain_are_rejected(self):
        self.chain("ep-c", 2)
        with self.assertRaises(ConflictError):
            self.store.append_event(make_event("ep-c", 2, "0" * 64))
        with self.assertRaises(ConflictError):
            self.store.append_event(make_event("ep-c", 5, self.store.head_digest("ep-c")))
        collision = make_event("ep-c", 2, self.store.head_digest("ep-c"),
                               event_id="ev-ep-c-0", key="fresh-key")
        with self.assertRaises(ConflictError):
            self.store.append_event(collision)
        key_reuse = make_event("ep-c", 2, self.store.head_digest("ep-c"),
                             event_id="fresh-id", key="key-ep-c-0")
        with self.assertRaises(ConflictError):
            self.store.append_event(key_reuse)

    def test_missing_artifact_reference_is_rejected(self):
        with self.assertRaises(ConflictError):
            self.store.append_event(make_event("ep-d", 0, None, artifacts=("0" * 64,)))

    def test_artifact_roundtrip_and_tamper_detection(self):
        digest = self.store.put_artifact(b"payload-bytes")
        self.assertTrue(self.store.has_artifact(digest))
        self.assertEqual(self.store.read_artifact(digest), b"payload-bytes")
        self.assertEqual(self.store.put_artifact(b"payload-bytes"), digest)
        artifact_path = self.store.root / "artifacts" / digest[:2] / digest
        artifact_path.write_bytes(b"evil")
        with self.assertRaises(IntegrityError):
            self.store.read_artifact(digest)
        with self.assertRaises(IntegrityError):
            self.store.read_artifact("f" * 64)
        with self.assertRaises(ContractError):
            self.store.read_artifact("not-a-digest")

    def test_oversized_artifact_is_rejected(self):
        with self.assertRaises(ContractError):
            self.store.put_artifact(b"x" * ((16 << 20) + 1))

    def test_crash_recovery_truncates_partial_tail(self):
        events = self.chain("ep-e", 2)
        path = self.store.root / "episodes" / "ep-e.jsonl"
        with open(path, "ab") as handle:
            handle.write(b'{"schema_version":1,"event_id":"partial')
        event = make_event("ep-e", 2, events[-1].digest)
        self.store.append_event(event)
        self.assertTrue(self.store.verify_episode("ep-e")["ok"])
        self.assertEqual(self.store.events("ep-e")[-1].event_id, event.event_id)

    def test_mid_file_tamper_is_detected_on_verify(self):
        self.chain("ep-f", 3)
        path = self.store.root / "episodes" / "ep-f.jsonl"
        data = path.read_bytes()
        marker = b'"note":"event-1"'
        self.assertIn(marker, data)
        path.write_bytes(data.replace(marker, b'"note":"forged!!"'))
        report = self.store.verify_episode("ep-f")
        self.assertFalse(report["ok"])
        self.assertTrue(any("chain_conflict" in p for p in report["problems"]), report)

    def test_anchor_head_exports_commitment_document(self):
        self.chain("ep-g", 2)
        anchor_dir = Path(self.temp.name) / "outside-custody"
        document = self.store.anchor_head("ep-g", anchor_dir)
        self.assertEqual(document["head_digest"], self.store.head_digest("ep-g"))
        self.assertEqual(document["event_count"], 2)
        self.assertTrue((anchor_dir / "ep-g.head.json").is_file())

    def test_anchor_refuses_corrupt_episode(self):
        self.chain("ep-h", 1)
        path = self.store.root / "episodes" / "ep-h.jsonl"
        path.write_bytes(path.read_bytes().replace(b"event-0", b"altered"))
        with self.assertRaises(IntegrityError):
            self.store.anchor_head("ep-h", Path(self.temp.name) / "anchor")

    def test_unknown_episode_and_invalid_id_fail_closed(self):
        with self.assertRaises(EpisodeStoreError):
            self.store.events("never-seen")
        self.assertFalse(self.store.verify_episode("never-seen")["ok"])
        with self.assertRaises(ContractError):
            self.store._episode_path("../escape")

    def test_episode_ids_lists_logs(self):
        self.chain("ep-i1", 1)
        self.chain("ep-i2", 1)
        self.assertIn("ep-i1", self.store.episode_ids())
        self.assertIn("ep-i2", self.store.episode_ids())


if __name__ == "__main__":
    unittest.main()
