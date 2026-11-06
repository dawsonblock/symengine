"""SIS3-009/010: hard-gated retrieval and recommend/abstain guidance."""
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sis.v3.contracts import ContractError, GuidanceRequestV1, ProcedureRecordV1
from sis.v3.guidance import sis_recommend
from sis.v3.retrieval import RetrievalContext, precondition_holds, retrieve

D = "0" * 64


def _request(**over):
    base = dict(
        schema_version=1, task_id="t1", repo_snapshot_digest=D, base_commit=None,
        namespace="ns", language="python", toolchain="cpython-3.12",
        lockfile_digests={}, task_summary="fix", failure_signatures=("sig-x",),
        present_symbols=("remaining_balance",), semantic_contract_digest=D,
    )
    base.update(over)
    return GuidanceRequestV1.from_dict(base)


def _proc(pid="p1", status="qualified", pre=({"kind": "language_is", "value": "python"},),
          contra=(), dist=None, cex=()):
    return ProcedureRecordV1(
        schema_version=1, procedure_id=pid, revision=1, intent="i",
        language="python", frameworks=(), task_signatures=("s",),
        failure_signatures=("sig-x",), preconditions=tuple(pre),
        contraindications=tuple(contra), steps=("s",),
        required_verification=("v",), counterexample_refs=tuple(cex),
        evidence_refs=(D,), outcome_distribution=dist or
        {"tasks": 2, "successes": 2, "failures": 0, "regressions": 0},
        status=status, expires_at=None,
    )


def _store(*records, root=None):
    """Build a real authority-backed catalog fixture.

    Qualified state is produced only through signed promotion decisions
    committed to an AuthorityDB — never by writing status fields directly.
    """
    from tests.v3.authority_testkit import authority_catalog
    return authority_catalog(root or Path(tempfile.mkdtemp()), *records)


class ExpiryRevocationTests(unittest.TestCase):
    """SIS-313: expired/revoked/stale procedures fail closed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.request = _request()

    def test_expired_record_abstains(self):
        record = replace(_proc(), expires_at="2020-01-01T00:00:00Z")
        store = _store(record)
        result = retrieve(self.request, store)
        self.assertEqual(result.candidates, ())
        self.assertEqual(result.rejections[0].reason_code, "expired")

    def test_malformed_expiry_rejected_at_contract(self):
        # Malformed timestamps can't even be minted — fail closed at parse.
        with self.assertRaises(ContractError):
            replace(_proc(), expires_at="not-a-date")

    def test_future_expiry_still_serves(self):
        record = replace(_proc(), expires_at="2999-01-01T00:00:00Z")
        store = _store(record)
        self.assertEqual(len(retrieve(self.request, store).candidates), 1)

    def test_revoked_digest_abstains_immediately(self):
        record = _proc()
        store = _store(record)
        self.assertEqual(len(retrieve(self.request, store).candidates), 1)
        # Revocation targets the live qualified revision's digest.
        live = store.get("p1")
        result = retrieve(self.request, store, revoked={live.digest})
        self.assertEqual(result.candidates, ())
        self.assertEqual(result.rejections[0].reason_code, "revoked")

    def test_now_injection_controls_expiry(self):
        record = replace(_proc(), expires_at="2030-01-01T00:00:00Z")
        store = _store(record)
        future = retrieve(self.request, store, now="2031-01-01T00:00:00Z")
        self.assertEqual(future.rejections[0].reason_code, "expired")
        self.assertEqual(len(retrieve(self.request, store, now="2029-01-01T00:00:00Z").candidates), 1)

    def test_guidance_passes_revocation_through(self):
        record = _proc()
        store = _store(record)
        served = sis_recommend(self.request, store)
        self.assertEqual(served.decision, "recommend")
        denied = sis_recommend(self.request, store, revoked={store.get("p1").digest})
        self.assertEqual(denied.decision, "abstain")
        self.assertEqual(denied.reason_code, "revoked")


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def ctx(self, **kw):
        base = dict(language="python", toolchain="cpython-3.12",
                    dependency_digests={"pip": D},
                    files_present=frozenset({"src/m.py"}),
                    symbols_present=frozenset({"f"}),
                    failure_signatures=frozenset({"sig-x"}))
        base.update(kw)
        return RetrievalContext(**base)

    def test_each_precondition_kind(self):
        c = self.ctx()
        self.assertTrue(precondition_holds({"kind": "language_is", "value": "python"}, c))
        self.assertFalse(precondition_holds({"kind": "language_is", "value": "rust"}, c))
        self.assertTrue(precondition_holds({"kind": "toolchain_is", "value": "cpython-3.12"}, c))
        self.assertTrue(precondition_holds(
            {"kind": "dependency_digest_is", "name": "pip", "digest": D}, c))
        self.assertFalse(precondition_holds(
            {"kind": "dependency_digest_is", "name": "pip", "digest": "f" * 64}, c))
        self.assertTrue(precondition_holds({"kind": "file_present", "value": "src/m.py"}, c))
        self.assertFalse(precondition_holds({"kind": "file_present", "value": "nope.py"}, c))
        self.assertTrue(precondition_holds({"kind": "symbol_present", "value": "f"}, c))
        self.assertTrue(precondition_holds({"kind": "failure_signature_is", "value": "sig-x"}, c))
        self.assertFalse(precondition_holds({"kind": "failure_signature_not", "value": "sig-x"}, c))
        with self.assertRaises(ContractError):
            precondition_holds({"kind": "exec_python", "value": "x"}, c)

    def test_qualified_survives_gates_and_is_returned(self):
        store = _store(_proc(pre=(
            {"kind": "language_is", "value": "python"},
            {"kind": "failure_signature_is", "value": "sig-x"},
        )), root=Path(self.temp.name) / "s")
        result = retrieve(_request(), store, files_present=("src/m.py",))
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].record.procedure_id, "p1")

    def test_unmet_precondition_rejects(self):
        store = _store(_proc(pre=({"kind": "language_is", "value": "rust"},)),
                       root=Path(self.temp.name) / "s")
        result = retrieve(_request(), store)
        self.assertFalse(result.candidates)
        self.assertEqual(result.rejections[0].reason_code, "precondition_failed")

    def test_contraindication_fires_negative_transfer(self):
        contra = ({"kind": "failure_signature_is", "value": "sig-x"},)
        store = _store(_proc(contra=contra, cex=("1" * 64,)),
                       root=Path(self.temp.name) / "s")
        result = retrieve(_request(), store)
        self.assertFalse(result.candidates)
        self.assertEqual(result.rejections[0].reason_code, "prior_negative_transfer")

    def test_nonqualified_not_retrieved(self):
        store = _store(_proc(status="candidate"), root=Path(self.temp.name) / "s")
        result = retrieve(_request(), store)
        self.assertFalse(result.candidates)
        self.assertEqual(result.rejections[-1].reason_code, "no_qualified_procedure")

    def test_ranking_prefers_more_evidence(self):
        weak = _proc(pid="weak", dist={"tasks": 2, "successes": 0, "failures": 2, "regressions": 0})
        strong = _proc(pid="strong", dist={"tasks": 5, "successes": 5, "failures": 0, "regressions": 0})
        store = _store(weak, strong, root=Path(self.temp.name) / "s")
        result = retrieve(_request(), store)
        self.assertEqual(result.candidates[0].record.procedure_id, "strong")


class GuidanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_recommend_returns_bound_record(self):
        store = _store(_proc(pre=(
            {"kind": "language_is", "value": "python"},
            {"kind": "symbol_present", "value": "remaining_balance"},
        )), root=self.root / "s")
        g = sis_recommend(_request(), store, files_present=("src/m.py",))
        self.assertEqual(g.decision, "recommend")
        self.assertEqual(g.procedure_ids, ("p1",))
        self.assertTrue(g.matched_preconditions)
        self.assertTrue(g.evidence_ids)
        self.assertIsNone(g.reason_code)

    def test_unverified_intent_still_abstains(self):
        store = _store(_proc(), root=self.root / "s")
        g = sis_recommend(_request(semantic_contract_digest=None), store)
        self.assertEqual(g.decision, "abstain")
        self.assertEqual(g.reason_code, "unverified_task_intent")

    def test_no_catalog_abstains(self):
        g = sis_recommend(_request(), None)
        self.assertEqual(g.decision, "abstain")
        self.assertEqual(g.reason_code, "no_qualified_procedure")

    def test_negative_transfer_fixture_abstains(self):
        """The audited Sub->Add false transfer must gate out, not recommend."""
        bad_proc = _proc(
            pre=({"kind": "language_is", "value": "python"},
                 {"kind": "symbol_present", "value": "remaining_balance"}),
            contra=({"kind": "symbol_present", "value": "remaining_balance"},),
            cex=("2" * 64,),
        )
        store = _store(bad_proc, root=self.root / "s")
        g = sis_recommend(_request(), store)
        self.assertEqual(g.decision, "abstain")
        self.assertEqual(g.reason_code, "prior_negative_transfer")
        self.assertFalse(g.procedure_ids)


if __name__ == "__main__":
    unittest.main()
