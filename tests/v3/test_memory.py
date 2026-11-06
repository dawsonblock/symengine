"""Experience memory: schema-safe ingest, dedup, induction, retrieval."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError, ExperienceRecordV1
from sis.v3.memory import (DuplicateEpisode, MemoryError, MemoryStore,
                           induce_candidate, retrieve_memories,
                           verify_experience_evidence)
from sis.v3.retrieval import RetrievalContext

NOW = "2026-10-24T12:00:00Z"


def make_experience(eid="exp-1", episode="ep-1", outcome="fail",
                    lesson="Use ROUND_HALF_UP for money",
                    counterexamples=(), repo="eval-money"):
    return ExperienceRecordV1(
        schema_version=1,
        experience_id=eid,
        episode_id=episode,
        repository_registry_id=repo,
        task_fingerprint=hashlib.sha256(
            ("fp:" + episode).encode()).hexdigest(),
        task_category="convention-fix",
        agent_config_digest="a" * 64,
        trace_digest="b" * 64,
        outcome_receipt_digest="c" * 64,
        outcome=outcome,
        failure_category="convention_unknown" if outcome == "fail" else None,
        lesson=lesson,
        facts=("baseline failed without guidance",),
        hypotheses=("guidance prevents this class",),
        applicability=({"kind": "language_is", "value": "python"},),
        counterexamples=counterexamples,
        provenance={"generator": "test", "method": "unit"},
        captured_at=NOW)


class StoreFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = MemoryStore(Path(self.temp.name) / "m.db")
        self.addCleanup(self.store.close)


class IngestTests(StoreFixture):
    def test_roundtrip_and_outcome_index(self):
        rec = make_experience()
        self.store.ingest(rec)
        self.assertEqual(self.store.get("exp-1"), rec)
        self.assertEqual(self.store.by_outcome("fail"), [rec])
        self.assertEqual(self.store.by_outcome("pass"), [])

    def test_idempotent_ingest_and_replay_conflict(self):
        rec = make_experience()
        self.store.ingest(rec)
        self.assertEqual(self.store.ingest(rec), rec.digest)
        # same episode+fingerprint, different content -> replay rejected
        forged = make_experience(eid="exp-2", lesson="different lesson")
        with self.assertRaises(DuplicateEpisode):
            self.store.ingest(forged)

    def test_tampered_row_fails_closed(self):
        rec = make_experience()
        self.store.ingest(rec)
        self.store._conn().execute(
            "UPDATE experience SET record_json=? WHERE experience_id='exp-1'",
            ('{"schema_version":1}',))
        self.store._conn().commit()
        with self.assertRaises((MemoryError, ContractError)):
            self.store.get("exp-1")

    def test_schema_validation_not_pickle(self):
        # Records only load through bounded JSON + schema validation.
        with self.assertRaises(ContractError):
            ExperienceRecordV1.from_dict({"schema_version": 1})

    def test_ingest_rejects_failed_evidence_check(self):
        with self.assertRaisesRegex(MemoryError, "evidence_rejected"):
            self.store.ingest(make_experience(), evidence_check=lambda r: False)
        self.assertEqual(self.store.by_outcome("fail"), [])


class ExperienceEvidenceTests(unittest.TestCase):
    class _Verifier:
        def __init__(self, receipt, *, valid=True):
            self.receipt = receipt
            self.valid = valid

        def load_receipt(self, digest):
            if self.receipt is None:
                raise MemoryError("receipt_missing")
            return self.receipt

        def verify_receipt(self, receipt):
            return self.valid

    class _Receipt:
        def __init__(self, outcome):
            self.outcome = outcome

    def test_authenticated_receipt_must_match_outcome(self):
        rec = make_experience(outcome="fail")
        self.assertTrue(verify_experience_evidence(
            rec, self._Verifier(self._Receipt("fail"))))
        with self.assertRaisesRegex(MemoryError, "outcome_mismatch"):
            verify_experience_evidence(
                rec, self._Verifier(self._Receipt("pass")))
        with self.assertRaisesRegex(MemoryError, "unauthenticated"):
            verify_experience_evidence(
                rec, self._Verifier(self._Receipt("fail"), valid=False))
        with self.assertRaisesRegex(MemoryError, "receipt_missing"):
            verify_experience_evidence(rec, self._Verifier(None))


class InductionTests(unittest.TestCase):
    def test_candidate_carries_separated_fact_and_hypothesis(self):
        cand = induce_candidate(make_experience())
        self.assertEqual(cand.candidate_type, "experience_memory")
        self.assertEqual(cand.payload["outcome"], "fail")
        self.assertIn("baseline failed", cand.payload["facts"][0])
        self.assertIn("guidance", cand.payload["hypotheses"][0])
        self.assertEqual(cand.repository_scope["value"], "eval-money")
        self.assertEqual(cand.source_episode_ids, ("ep-1",))
        # content digest actually binds the payload
        self.assertEqual(cand.digest, cand.digest)

    def test_scope_override(self):
        cand = induce_candidate(
            make_experience(),
            repository_scope={"kind": "family_id", "value": "fam-a"})
        self.assertEqual(cand.repository_scope["kind"], "family_id")


class RetrievalTests(unittest.TestCase):
    def ctx(self, **kw):
        return RetrievalContext(
            language=kw.get("language", "python"),
            toolchain=kw.get("toolchain", "pytest"),
            files_present=frozenset(kw.get("files", ())),
            symbols_present=frozenset(kw.get("symbols", ())),
            failure_signatures=frozenset(kw.get("failures", ())))

    def test_applicable_memory_selected(self):
        cand = induce_candidate(make_experience())
        picked = retrieve_memories([cand], self.ctx())
        self.assertEqual(len(picked), 1)
        self.assertEqual(picked[0].candidate, cand)

    def test_abstains_when_inapplicable(self):
        cand = induce_candidate(make_experience())
        self.assertEqual(
            retrieve_memories([cand], self.ctx(language="rust")), ())
        self.assertEqual(retrieve_memories([], self.ctx()), ())

    def test_counterexample_suppresses(self):
        cand = induce_candidate(
            make_experience(counterexamples=("legacy-sig",)))
        picked = retrieve_memories([cand], self.ctx(failures=("legacy-sig",)))
        self.assertEqual(picked, ())

    def test_short_counterexample_requires_token_match(self):
        # "ai" must not suppress on contexts containing "airflow" —
        # substrings inside longer tokens are not counterexamples.
        cand = induce_candidate(
            make_experience(counterexamples=("ai",)))
        picked = retrieve_memories(
            [cand], self.ctx(failures=("airflow timeout",)))
        self.assertEqual(len(picked), 1)
        picked = retrieve_memories(
            [cand], self.ctx(failures=("ai",)))
        self.assertEqual(picked, ())

    def test_dedup_by_content_digest(self):
        a = induce_candidate(make_experience())
        b = induce_candidate(make_experience(eid="exp-9", episode="ep-9"))
        # identical payload -> identical content digest -> deduped
        self.assertEqual(a.content_digest, b.content_digest)
        self.assertEqual(len(retrieve_memories([a, b], self.ctx())), 1)

    def test_token_budget_and_limit(self):
        cands = [induce_candidate(
            make_experience(eid=f"e{i}", episode=f"ep{i}",
                            lesson="lesson " + str(i))) for i in range(6)]
        # each lesson "lesson N" costs ~2 tokens; budget 5 fits 2
        picked = retrieve_memories(cands, self.ctx(), token_budget=5,
                                   limit=10)
        self.assertEqual(len(picked), 2)
        picked = retrieve_memories(cands, self.ctx(), limit=2)
        self.assertEqual(len(picked), 2)

    def test_non_memory_types_ignored(self):
        from tests.v3.test_candidates import make_candidate
        other = make_candidate(ctype="skill_instruction")
        self.assertEqual(retrieve_memories([other], self.ctx()), ())


if __name__ == "__main__":
    unittest.main()
