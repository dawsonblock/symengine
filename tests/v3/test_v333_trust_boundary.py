"""SIS v3.3.3 trust-boundary regression tests (post-3.3.2 audit, gate G0).

Red reproductions of the five audited defects. Each asserts the repaired
contract, so on the defective tree they fail:

- T1: LocalSubprocessExecutor self-certifies ``isolation:verified`` and a
  bare marker qualifies a production TASK_PASS without any attestation.
- T2: verify_experience_evidence authenticates a receipt's signature and
  outcome but never binds the record's task, repository snapshot, attempt
  or execution receipt — an unrelated receipt is accepted.
- T3: a memory-DB writer that changes record_json and record_digest
  together is not detected; the row-local checksum is unkeyed.
- T4: the representable 16-input rule ``x14*x15+2`` is starved by fixed
  enumeration order inside a 50k candidate budget.
- T5: release/ provenance (375 files, commit 17f6360) describes an older
  source than the current 382-file tree at HEAD with no check failing.
"""
from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sis.v3 import signatures
from sis.v3.contracts import (
    ContractError,
    ExperienceRecordV1,
    TaskEnvelopeV1,
    canonical_digest,
)
from sis.v3.evaluation_runtime import (
    SANDBOX_FAILURE,
    classify_execution,
)
from sis.v3.memory import (
    MemoryError,
    MemoryStore,
    verify_experience_evidence,
)
from sis.v3.runner import (
    CommandSpec,
    LocalSubprocessExecutor,
    ResourceLimits,
)
from sis.v3.verifier import (
    EvaluationRejected,
    JournalIntegrityError,
    OutcomeVerifier,
    verify_receipt_signature,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-11-08T12:00:00Z"


def _base_tree(root: Path) -> Path:
    base = root / "base"
    base.mkdir()
    (base / "README.txt").write_text("fixture\n")
    return base


def _limits(**kw) -> ResourceLimits:
    defaults = dict(
        cpu_seconds=20, wall_seconds=15, memory_bytes=1 << 30,
        output_bytes=1 << 20, disk_bytes=16 << 20, process_count=64)
    defaults.update(kw)
    return ResourceLimits(**defaults)


ACCEPTANCE = (
    b"import calc\n"
    b"assert calc.scale(3, 4) == 12\n"
    b"print('ok')\n"
)


def _task_envelope(task_id="task-scale") -> TaskEnvelopeV1:
    return TaskEnvelopeV1(
        schema_version=1, task_id=task_id,
        repo_snapshot_digest="0" * 64, base_commit=None,
        task_statement_digest="1" * 64,
        permitted_commands=("run-tests",), isolation_profile="unverified_local",
        time_budget_seconds=300, token_budget=10_000, tool_budget=50,
        actor_id="agent-1", evaluator_task_ref=task_id,
    )


class LocalSelfCertificationTests(unittest.TestCase):
    """T1: this backend can never mint a verified-isolation claim."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = _base_tree(self.root)

    def test_production_constructor_rejects_verified_isolation(self):
        with self.assertRaises(ContractError):
            LocalSubprocessExecutor(
                self.root / "exec", use_seatbelt=False,
                production=True, verified_isolation=True)

    def test_development_constructor_rejects_verified_isolation(self):
        # The flag mints the marker on every receipt, not only production
        # runs, so it is rejected for this backend unconditionally.
        with self.assertRaises(ContractError):
            LocalSubprocessExecutor(
                self.root / "exec", use_seatbelt=False,
                verified_isolation=True)

    def test_local_receipt_is_always_unverified_local(self):
        executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False)
        workspace = executor.prepare(self.base)
        receipt = executor.run(workspace, CommandSpec(
            argv=(sys.executable, "-c", "print(1)"), limits=_limits()))
        markers = set(receipt.security_errors)
        self.assertIn("isolation:unverified_local", markers)
        self.assertNotIn("isolation:verified", markers)

    def test_production_still_refuses_local_execution(self):
        executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False, production=True)
        workspace = executor.prepare(self.base)
        with self.assertRaisesRegex(
                Exception, "not_production_qualified"):
            executor.run(workspace, CommandSpec(
                argv=(sys.executable, "-c", "print(1)"), limits=_limits()))


class FabricatedMarkerTests(unittest.TestCase):
    """T1 classification half: a self-reported marker is not an attestation."""

    def test_bare_verified_marker_is_not_production_qualified(self):
        receipt = SimpleNamespace(
            security_errors=("isolation:verified",),
            timeout=False, exit_status=0)
        self.assertEqual(
            classify_execution(receipt, production=True), SANDBOX_FAILURE)

    def test_marker_manipulation_cannot_mint_task_pass(self):
        for markers in (
            ("isolation:verified",),
            ("isolation:verified", "network:seatbelt_denied"),
            ("isolation:verified", "isolation:seatbelt"),
        ):
            with self.subTest(markers=markers):
                receipt = SimpleNamespace(
                    security_errors=markers, timeout=False, exit_status=0)
                self.assertEqual(
                    classify_execution(receipt, production=True),
                    SANDBOX_FAILURE)

    def test_marker_manipulation_cannot_mint_task_fail_or_timeout(self):
        receipt = SimpleNamespace(
            security_errors=("isolation:verified",),
            timeout=False, exit_status=1)
        self.assertEqual(
            classify_execution(receipt, production=True), SANDBOX_FAILURE)
        receipt = SimpleNamespace(
            security_errors=("isolation:verified",),
            timeout=True, exit_status=-1)
        self.assertEqual(
            classify_execution(receipt, production=True), SANDBOX_FAILURE)

    def test_unverified_local_marker_disqualifies_even_when_attested(self):
        # production=True is fail-closed; a local marker can never qualify.
        receipt = SimpleNamespace(
            security_errors=("isolation:unverified_local",),
            timeout=False, exit_status=0)
        self.assertEqual(
            classify_execution(receipt, production=True), SANDBOX_FAILURE)


class IsolationAttestationTests(unittest.TestCase):
    """T1 attestation half: signed, bound, policy-checked isolation proof."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = _base_tree(self.root)
        self.seed, self.public = signatures.generate_keypair()
        self.keys = {"isolator-1": self.public.hex()}
        executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False,
            worker_identity="worker-A")
        workspace = executor.prepare(self.base)
        self.spec = CommandSpec(
            argv=(sys.executable, "-c", "print(1)"), limits=_limits())
        self.receipt = executor.run(workspace, self.spec)

    def _issue(self, receipt=None, seed=None, key_id="isolator-1",
               **overrides):
        from sis.v3.isolation import issue_attestation
        receipt = receipt or self.receipt
        fields = dict(
            attestation_id="att-1",
            backend="linux-rootless-worker",
            worker_identity="worker-A",
            policy_digest="aa" * 32,
            image_digest="bb" * 32,
            command_spec_digest=receipt.command_spec_digest,
            workspace_input_digest=receipt.before_tree_digest,
            execution_receipt_digest=receipt.digest,
            properties=("fs:workspace_confined", "net:denied",
                        "proc:namespaced"),
            issued_at=NOW, expires_at="2027-01-01T00:00:00Z",
            nonce="nonce-1")
        fields.update(overrides)
        return issue_attestation(
            seed or self.seed, key_id=key_id, **fields)

    def _verify(self, attestation, receipt=None, **kw):
        from sis.v3.isolation import verify_isolation_attestation
        kw.setdefault("trusted_keys", self.keys)
        kw.setdefault("allowed_backends", ("linux-rootless-worker",))
        kw.setdefault("at_time", "2026-11-08T13:00:00Z")
        return verify_isolation_attestation(
            attestation, receipt or self.receipt, **kw)

    def test_correctly_bound_attestation_verifies(self):
        self.assertTrue(self._verify(self._issue()))

    def test_attestation_for_other_receipt_rejected(self):
        executor = LocalSubprocessExecutor(
            self.root / "exec2", use_seatbelt=False,
            worker_identity="worker-A")
        workspace = executor.prepare(self.base)
        other = executor.run(workspace, CommandSpec(
            argv=(sys.executable, "-c", "print(2)"), limits=_limits()))
        attestation = self._issue(execution_receipt_digest=other.digest)
        self.assertFalse(self._verify(attestation))

    def test_attestation_for_other_command_rejected(self):
        self.assertFalse(self._verify(
            self._issue(command_spec_digest="f" * 64)))

    def test_attestation_for_other_tree_rejected(self):
        self.assertFalse(self._verify(
            self._issue(workspace_input_digest="f" * 64)))

    def test_attestation_for_other_worker_rejected(self):
        self.assertFalse(self._verify(
            self._issue(worker_identity="worker-B")))

    def test_expired_attestation_rejected(self):
        attestation = self._issue(expires_at="2026-11-08T12:30:00Z")
        self.assertFalse(self._verify(
            attestation, at_time="2026-11-08T13:00:00Z"))
        self.assertTrue(self._verify(
            attestation, at_time="2026-11-08T12:15:00Z"))

    def test_wrong_signer_rejected(self):
        seed, _public = signatures.generate_keypair()
        self.assertFalse(self._verify(self._issue(seed=seed)))
        self.assertFalse(self._verify(
            self._issue(key_id="isolator-unknown")))

    def test_unallowlisted_backend_rejected(self):
        attestation = self._issue(backend="local-subprocess")
        self.assertFalse(self._verify(attestation))
        self.assertFalse(self._verify(
            self._issue(), allowed_backends=("microvm",)))

    def test_policy_mismatch_rejected(self):
        self.assertFalse(self._verify(
            self._issue(), required_policy_digest="cc" * 32))
        self.assertTrue(self._verify(
            self._issue(), required_policy_digest="aa" * 32))

    def test_attested_production_classification(self):
        # A preconstructed positive verification object is not an
        # attestation; the evaluator-owned route rejects it.
        from sis.v3.evaluation_runtime import classify_production_execution
        from sis.v3.isolation import (
            IsolationVerification,
            ProductionIsolationPolicy,
        )
        digest = "a" * 64
        receipt = SimpleNamespace(
            security_errors=("net:denied",), timeout=False, exit_status=0,
            digest=digest, command_spec_digest="b" * 64,
            before_tree_digest="c" * 64, worker_identity="worker-A")
        policy = ProductionIsolationPolicy(
            allowed_backends=frozenset({"linux-rootless-worker"}),
            trusted_keys=self.keys,
            required_policy_digest="aa" * 32,
            required_image_digest="bb" * 32,
            required_properties=frozenset({"net:denied"}))
        forged = IsolationVerification(
            ok=True, reason="ok", receipt_digest=digest)
        result = classify_production_execution(receipt, forged, policy)
        self.assertEqual(result.outcome_class, SANDBOX_FAILURE)
        self.assertFalse(result.verification.ok)


def _v1_record(**over):
    fields = dict(
        schema_version=1,
        experience_id="exp-1", episode_id="ep-1",
        repository_registry_id="repo-a",
        task_fingerprint=hashlib.sha256(b"fp:ep-1").hexdigest(),
        task_category="convention-fix",
        agent_config_digest="a" * 64,
        trace_digest="b" * 64,
        outcome_receipt_digest="c" * 64,
        outcome="fail", failure_category="convention_unknown",
        lesson="Use ROUND_HALF_UP for money",
        facts=("baseline failed without guidance",),
        hypotheses=("guidance prevents this class",),
        applicability=({"kind": "language_is", "value": "python"},),
        counterexamples=(),
        provenance={"generator": "test", "method": "unit"},
        captured_at=NOW)
    fields.update(over)
    return ExperienceRecordV1(**fields)


def _v2_record(seed, key_id="exp-key-1", **over):
    from sis.v3.memory import issue_experience_record
    fields = dict(
        experience_id="exp-1", episode_id="ep-1",
        repository_registry_id="repo-a",
        task_id="task-A", attempt_id="att-1",
        repo_snapshot_digest="d" * 64,
        task_fingerprint=hashlib.sha256(b"fp:ep-1").hexdigest(),
        task_category="convention-fix",
        agent_config_digest="a" * 64,
        execution_receipt_digest="e" * 64,
        trace_digest="b" * 64,
        outcome_receipt_digest="c" * 64,
        outcome="fail", failure_category="convention_unknown",
        lesson="Use ROUND_HALF_UP for money",
        facts=("baseline failed without guidance",),
        hypotheses=("guidance prevents this class",),
        applicability=({"kind": "language_is", "value": "python"},),
        counterexamples=(),
        provenance={"generator": "test", "method": "unit"},
        captured_at=NOW)
    fields.update(over)
    return issue_experience_record(seed, key_id, **fields)


class _Envelope:
    """Outcome-envelope-shaped test artifact (task+repo+attempt+exec)."""

    def __init__(self, task_id="task-A", repo="d" * 64, attempt="att-1",
                 execution="e" * 64, outcome="fail", digest="c" * 64):
        self.digest = digest
        self.task_id = task_id
        self.evaluated_repo_digest = repo
        self.attempt_id = attempt
        self.execution_receipt_digest = execution
        self.outcome = outcome


class _Verifier:
    """Minimal verifier double: authenticates and resolves one artifact."""

    def __init__(self, artifact, *, valid=True, journal_exec=None):
        self.artifact = artifact
        self.valid = valid
        self.journal_exec = journal_exec

    def load_receipt(self, digest):
        if self.artifact is None:
            raise MemoryError("receipt_missing")
        return self.artifact

    def verify_receipt(self, artifact):
        return self.valid

    def execution_digest_for(self, receipt_digest):
        return self.journal_exec


class ExperienceLineageTests(unittest.TestCase):
    """T2: evidence must bind task, repo snapshot, attempt and execution."""

    def setUp(self):
        self.seed, _public = signatures.generate_keypair()

    def test_authenticated_matching_lineage_passes(self):
        record = _v2_record(self.seed)
        verifier = _Verifier(_Envelope())
        self.assertTrue(verify_experience_evidence(record, verifier))

    def test_receipt_for_other_task_rejected(self):
        record = _v2_record(self.seed, task_id="task-A")
        verifier = _Verifier(_Envelope(task_id="task-B"))
        with self.assertRaisesRegex(MemoryError, "task_mismatch"):
            verify_experience_evidence(record, verifier)

    def test_receipt_for_other_repository_rejected(self):
        record = _v2_record(self.seed)
        verifier = _Verifier(_Envelope(repo="f" * 64))
        with self.assertRaisesRegex(MemoryError, "repo_mismatch"):
            verify_experience_evidence(record, verifier)

    def test_receipt_for_other_attempt_rejected(self):
        record = _v2_record(self.seed)
        verifier = _Verifier(_Envelope(attempt="att-9"))
        with self.assertRaisesRegex(MemoryError, "attempt_mismatch"):
            verify_experience_evidence(record, verifier)

    def test_receipt_for_other_execution_rejected(self):
        record = _v2_record(self.seed)
        verifier = _Verifier(_Envelope(execution="9" * 64))
        with self.assertRaisesRegex(MemoryError, "execution_mismatch"):
            verify_experience_evidence(record, verifier)

    def test_outcome_mismatch_still_rejected(self):
        record = _v2_record(self.seed, outcome="fail")
        verifier = _Verifier(_Envelope(outcome="pass"))
        with self.assertRaisesRegex(MemoryError, "outcome_mismatch"):
            verify_experience_evidence(record, verifier)

    def test_unauthenticated_receipt_still_rejected(self):
        record = _v2_record(self.seed)
        verifier = _Verifier(_Envelope(), valid=False)
        with self.assertRaisesRegex(MemoryError, "unauthenticated"):
            verify_experience_evidence(record, verifier)

    def test_v1_receipt_without_execution_linkage_rejected(self):
        # A V1-shaped receipt carries task/repo/outcome but no attempt or
        # execution digest; without a corroborating journal the claimed
        # execution_receipt_digest is unverifiable -> fail closed.
        record = _v2_record(self.seed)
        receipt = SimpleNamespace(
            digest="c" * 64,
            task_id="task-A", evaluated_repo_digest="d" * 64,
            outcome="fail")
        verifier = _Verifier(receipt, journal_exec=None)
        verifier.execution_digest_for = None
        with self.assertRaisesRegex(MemoryError, "execution_unverifiable"):
            verify_experience_evidence(record, verifier)
        verifier = _Verifier(receipt, journal_exec="9" * 64)
        with self.assertRaisesRegex(MemoryError, "execution_mismatch"):
            verify_experience_evidence(record, verifier)
        verifier = _Verifier(receipt, journal_exec="e" * 64)
        self.assertTrue(verify_experience_evidence(record, verifier))

    def test_v1_records_are_legacy_not_verified_evidence(self):
        record = _v1_record()
        verifier = _Verifier(_Envelope())
        with self.assertRaisesRegex(MemoryError, "legacy_unverifiable"):
            verify_experience_evidence(record, verifier)


class ReceiptIdentityTests(unittest.TestCase):
    """G1: a receipt reference resolves to exactly one authenticated artifact.

    A signature that verifies over some other evaluation is never evidence
    for the address it was stored under, so every substitution below must
    fail closed at both the verifier and the memory boundary.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.submission = self.root / "submission"
        self.submission.mkdir()
        (self.submission / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n", encoding="utf-8")
        (self.submission / "README.txt").write_text("variant-1\n")
        self.verifier = self._verifier("registry-1", "keys-1")
        self.verifier.register_task(
            actor_role="evaluator", task_id="task-scale",
            criterion_version="acceptance-v1",
            argv=(sys.executable, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE})
        self.receipt_a = self._evaluate(self.verifier, "nonce-a")

    def _verifier(self, registry, keys, criterion="acceptance-v1"):
        verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(
                self.root / ("exec-" + registry), use_seatbelt=False),
            key_dir=self.root / keys,
            registry_dir=self.root / registry)
        verifier.register_task(
            actor_role="evaluator", task_id="task-scale",
            criterion_version=criterion,
            argv=(sys.executable, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE})
        return verifier

    def _evaluate(self, verifier, nonce):
        return verifier.evaluate(
            actor_role="evaluator", task=_task_envelope(),
            submission_dir=self.submission, evaluation_nonce=nonce)

    def _second_receipt(self):
        (self.submission / "README.txt").write_text("variant-2\n")
        return self._evaluate(self.verifier, "nonce-b")

    def _receipt_path(self, registry, digest):
        return self.root / registry / "receipts" / f"{digest}.json"

    def _substitute(self, other_digest, source="registry-1"):
        self._receipt_path("registry-1", self.receipt_a.digest).write_bytes(
            self._receipt_path(source, other_digest).read_bytes())

    def _restart(self, registry="registry-1", keys="keys-1"):
        return OutcomeVerifier(
            executor=LocalSubprocessExecutor(
                self.root / "exec-restart", use_seatbelt=False),
            key_dir=self.root / keys,
            registry_dir=self.root / registry)

    def _rewrite_journal(self, **changes):
        path = self.root / "registry-1" / "receipts.jsonl"
        lines = [json.loads(line) for line in path.read_bytes().splitlines()]
        for entry in lines:
            if entry["receipt_digest"] == self.receipt_a.digest:
                entry.update(changes)
        path.write_bytes(b"".join(
            json.dumps(entry).encode() + b"\n" for entry in lines))

    def test_valid_receipt_for_another_evaluation_rejected(self):
        b = self._second_receipt()
        self.assertNotEqual(self.receipt_a.digest, b.digest)
        self.assertNotEqual(self.receipt_a.receipt_id, b.receipt_id)
        self.assertNotEqual(
            self.receipt_a.evaluated_repo_digest, b.evaluated_repo_digest)
        self._substitute(b.digest)
        with self.assertRaisesRegex(
                JournalIntegrityError, "receipt_digest_mismatch"):
            self.verifier.load_receipt(self.receipt_a.digest)

    def test_substitution_detected_on_restart(self):
        b = self._second_receipt()
        self._substitute(b.digest)
        with self.assertRaisesRegex(
                JournalIntegrityError, "receipt_digest_mismatch"):
            self._restart()

    def test_valid_receipt_under_another_signer_rejected(self):
        other = self._verifier("registry-2", "keys-2")
        receipt_c = self._evaluate(other, "nonce-c")
        self.assertTrue(verify_receipt_signature(
            receipt_c, other.public_key_record()["public_key"]))
        self.assertFalse(verify_receipt_signature(
            receipt_c, self.verifier.public_key_record()["public_key"]))
        self._substitute(receipt_c.digest, source="registry-2")
        with self.assertRaisesRegex(
                JournalIntegrityError, "receipt_digest_mismatch"):
            self.verifier.load_receipt(self.receipt_a.digest)

    def test_same_task_different_protocol_rejected(self):
        other = self._verifier("registry-2", "keys-2", criterion="acceptance-v2")
        receipt_d = self._evaluate(other, "nonce-d")
        self.assertEqual(receipt_d.task_id, self.receipt_a.task_id)
        self.assertEqual(
            receipt_d.evaluated_repo_digest, self.receipt_a.evaluated_repo_digest)
        self.assertEqual(receipt_d.outcome, self.receipt_a.outcome)
        self.assertNotEqual(
            receipt_d.criterion_version, self.receipt_a.criterion_version)
        self.assertNotEqual(
            receipt_d.test_suite_commitment, self.receipt_a.test_suite_commitment)
        self._substitute(receipt_d.digest, source="registry-2")
        with self.assertRaisesRegex(
                JournalIntegrityError, "receipt_digest_mismatch"):
            self.verifier.load_receipt(self.receipt_a.digest)

    def test_missing_receipt_fails_closed(self):
        with self.assertRaisesRegex(JournalIntegrityError, "receipt_missing"):
            self.verifier.load_receipt("0" * 64)

    def test_altered_receipt_contents_fail_closed(self):
        path = self._receipt_path("registry-1", self.receipt_a.digest)
        document = json.loads(path.read_bytes())
        document["outcome"] = "pass" if document["outcome"] != "pass" else "fail"
        path.write_bytes(json.dumps(document).encode())
        with self.assertRaisesRegex(
                JournalIntegrityError, "receipt_digest_mismatch"):
            self.verifier.load_receipt(self.receipt_a.digest)

        path.write_bytes(b"{not-json")
        with self.assertRaisesRegex(
                JournalIntegrityError, "receipt_malformed"):
            self.verifier.load_receipt(self.receipt_a.digest)

    def test_replayed_receipt_rejected(self):
        with self.assertRaisesRegex(EvaluationRejected, "replayed_nonce"):
            self._evaluate(self.verifier, "nonce-a")
        with self.assertRaisesRegex(EvaluationRejected, "duplicate_evaluation"):
            self._evaluate(self.verifier, "nonce-replay")

        journal = self.root / "registry-1" / "receipts.jsonl"
        first_line = journal.read_bytes().splitlines()[0]
        journal.write_bytes(journal.read_bytes() + first_line + b"\n")
        with self.assertRaisesRegex(JournalIntegrityError, "duplicates a receipt"):
            self._restart()

    def test_corrupted_journal_fails_closed(self):
        for field, value in (
                ("task_id", "task-other"),
                ("criterion_version", "acceptance-v9"),
                ("outcome", "pass" if self.receipt_a.outcome != "pass" else "fail"),
                ("signer_key_id", "key-other"),
        ):
            with self.subTest(field=field):
                journal = self.root / "registry-1" / "receipts.jsonl"
                original = journal.read_bytes()
                self._rewrite_journal(**{field: value})
                with self.assertRaisesRegex(
                        JournalIntegrityError, "receipt_journal_mismatch"):
                    self._restart()
                journal.write_bytes(original)

    def test_legacy_journal_without_signer_field_still_loads(self):
        journal = self.root / "registry-1" / "receipts.jsonl"
        lines = [json.loads(line) for line in journal.read_bytes().splitlines()]
        for entry in lines:
            entry.pop("signer_key_id", None)
        journal.write_bytes(b"".join(
            json.dumps(entry).encode() + b"\n" for entry in lines))
        restarted = self._restart()
        self.assertIsNotNone(
            restarted.execution_digest_for(self.receipt_a.digest))

    def test_journal_entry_missing_required_field_fails_closed(self):
        journal = self.root / "registry-1" / "receipts.jsonl"
        original = journal.read_bytes()
        lines = [json.loads(line) for line in original.splitlines()]
        for entry in lines:
            entry.pop("execution_digest", None)
        journal.write_bytes(b"".join(
            json.dumps(entry).encode() + b"\n" for entry in lines))
        with self.assertRaisesRegex(JournalIntegrityError, "is missing"):
            self._restart()
        journal.write_bytes(original)

    def test_unverified_journal_entry_cannot_corroborate_execution(self):
        self.assertIsNotNone(
            self.verifier.execution_digest_for(self.receipt_a.digest))
        self._receipt_path("registry-1", self.receipt_a.digest).unlink()
        restarted = self._restart()
        self.assertIsNone(restarted.execution_digest_for(self.receipt_a.digest))

    def test_memory_rejects_resolver_substitution(self):
        b = self._second_receipt()
        seed, _public = signatures.generate_keypair()
        record = _v2_record(
            seed,
            outcome_receipt_digest=self.receipt_a.digest,
            task_id=b.task_id,
            repo_snapshot_digest=b.evaluated_repo_digest,
            execution_receipt_digest=self.verifier.execution_digest_for(b.digest),
            outcome=b.outcome,
        )

        class _SubstitutingResolver:
            def load_receipt(self, digest):
                return b

            def verify_receipt(self, artifact):
                return True

            def execution_digest_for(self, digest):
                return None

        with self.assertRaisesRegex(
                MemoryError, "experience_receipt_digest_mismatch"):
            verify_experience_evidence(record, _SubstitutingResolver())

    def test_memory_accepts_authentic_lineage(self):
        seed, _public = signatures.generate_keypair()
        record = _v2_record(
            seed,
            outcome_receipt_digest=self.receipt_a.digest,
            task_id=self.receipt_a.task_id,
            repo_snapshot_digest=self.receipt_a.evaluated_repo_digest,
            execution_receipt_digest=self.verifier.execution_digest_for(
                self.receipt_a.digest),
            outcome=self.receipt_a.outcome,
        )
        self.assertTrue(verify_experience_evidence(record, self.verifier))


class MemoryTamperTests(unittest.TestCase):
    """T3: DB-row checksums are not provenance signatures."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "m.db"
        self.seed, self.public = signatures.generate_keypair()
        self.keys = {"exp-key-1": self.public.hex()}

    def test_coordinated_json_and_digest_rewrite_detected(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys)
        self.addCleanup(store.close)
        original = _v2_record(self.seed)
        store.ingest(original)
        # The adversary edits the lesson and rewrites both columns. The
        # signature field it copies no longer covers the body.
        forged = dict(original.to_dict())
        forged["lesson"] = "Always floor monetary division"
        forged_row = json.dumps(
            forged, sort_keys=True, separators=(",", ":"))
        forged_digest = canonical_digest(
            "experience_record_v2", 1, json.loads(forged_row))
        store._conn().execute(
            "UPDATE experience SET record_json=?, record_digest=?"
            " WHERE experience_id='exp-1'",
            (forged_row, forged_digest))
        with self.assertRaisesRegex(MemoryError, "tampered|chain"):
            store.get("exp-1")

    def test_unsigned_v1_rejected_when_keys_configured(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys)
        self.addCleanup(store.close)
        with self.assertRaisesRegex(MemoryError, "untrusted"):
            store.ingest(_v1_record())

    def test_v2_signed_by_untrusted_key_rejected(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys)
        self.addCleanup(store.close)
        other_seed, other_pub = signatures.generate_keypair()
        with self.assertRaisesRegex(MemoryError, "untrusted"):
            store.ingest(_v2_record(other_seed, key_id="other-key"))
        with self.assertRaisesRegex(MemoryError, "tampered"):
            store.ingest(_v2_record(other_seed))

    def test_signed_v2_roundtrip(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys)
        self.addCleanup(store.close)
        record = _v2_record(self.seed)
        self.assertEqual(store.ingest(record), record.digest)
        self.assertEqual(store.get("exp-1"), record)
        self.assertEqual(store.by_outcome("fail"), [record])

    def test_legacy_store_keeps_v1_rows(self):
        store = MemoryStore(self.db)
        self.addCleanup(store.close)
        record = _v1_record()
        store.ingest(record)
        self.assertEqual(store.get("exp-1"), record)

    def test_deleted_row_breaks_chain(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys)
        self.addCleanup(store.close)
        store.ingest(_v2_record(self.seed))
        store.ingest(_v2_record(self.seed, experience_id="exp-2",
                                episode_id="ep-2"))
        store._conn().execute(
            "DELETE FROM experience WHERE experience_id='exp-1'")
        self.assertFalse(store.verify_chain())
        with self.assertRaisesRegex(MemoryError, "chain"):
            store.get("exp-2")
        with self.assertRaisesRegex(MemoryError, "chain"):
            store.by_outcome("fail")

    def test_deleted_chain_entry_detected(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys)
        self.addCleanup(store.close)
        store.ingest(_v2_record(self.seed))
        store.ingest(_v2_record(self.seed, experience_id="exp-2",
                                episode_id="ep-2"))
        store._conn().execute("DELETE FROM memory_chain WHERE seq=1")
        self.assertFalse(store.verify_chain())
        with self.assertRaisesRegex(MemoryError, "chain"):
            store.get("exp-2")

    def test_snapshot_rewind_detected_by_pinned_head(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys)
        self.addCleanup(store.close)
        store.ingest(_v2_record(self.seed))
        pinned = store.head_digest()
        self.assertIsNotNone(pinned)
        self.assertTrue(store.verify_chain(expected_head=pinned))
        store.ingest(_v2_record(self.seed, experience_id="exp-2",
                                episode_id="ep-2"))
        # An older snapshot's head can no longer stand in for current state.
        self.assertFalse(store.verify_chain(expected_head=pinned))
        self.assertTrue(store.verify_chain())

    def test_forged_chain_entry_detected(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys,
                            chain_key=(self.seed, "exp-key-1"))
        self.addCleanup(store.close)
        store.ingest(_v2_record(self.seed))
        store.ingest(_v2_record(self.seed, experience_id="exp-2",
                                episode_id="ep-2"))
        # Adversary with file access but no seed cannot forge the chain.
        forged_head = "f" * 64
        store._conn().execute(
            "UPDATE memory_chain SET head=?, signature=? WHERE seq=2",
            (forged_head, "00" * 64))
        self.assertFalse(store.verify_chain())
        with self.assertRaisesRegex(MemoryError, "chain"):
            store.get("exp-1")


class ChainMigrationTests(unittest.TestCase):
    """Pre-chain databases: reads fail named, repair restores them."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "m.db"
        self.seed, self.public = signatures.generate_keypair()
        self.keys = {"exp-key-1": self.public.hex()}

    def test_unchained_rows_report_unmigrated(self):
        store = MemoryStore(self.db)
        store.ingest(_v1_record())
        # A database written before the chain existed: rows present, no
        # chain entries (the table arrives empty via schema upgrade).
        store._conn().execute("DELETE FROM memory_chain")
        store.close()
        store = MemoryStore(self.db, trusted_signer_keys=self.keys)
        self.addCleanup(store.close)
        with self.assertRaisesRegex(MemoryError, "memory_unmigrated"):
            store.get("exp-1")
        with self.assertRaisesRegex(MemoryError, "memory_unmigrated"):
            store.by_outcome("fail")
        with self.assertRaisesRegex(MemoryError, "memory_unmigrated"):
            store.ingest(_v2_record(self.seed))
        self.assertEqual(store.last_chain_failure, "unchained_rows")
        self.assertFalse(store.verify_chain())

    def test_repair_chain_backfills_then_serves(self):
        store = MemoryStore(self.db)
        store.ingest(_v1_record())
        store.ingest(_v1_record(experience_id="exp-2", episode_id="ep-2"))
        store._conn().execute("DELETE FROM memory_chain")
        store.close()
        store = MemoryStore(self.db, trusted_signer_keys=self.keys,
                            chain_key=(self.seed, "exp-key-1"))
        self.addCleanup(store.close)
        self.assertEqual(store.repair_chain(), 2)
        self.assertTrue(store.verify_chain())
        self.assertIsNone(store.last_chain_failure)
        # Chaining attests membership, not provenance: the V1 row stays
        # legacy-untrusted on read while new signed records serve.
        with self.assertRaisesRegex(MemoryError, "untrusted"):
            store.get("exp-1")
        record = _v2_record(self.seed, experience_id="exp-3",
                            episode_id="ep-3")
        store.ingest(record)
        self.assertEqual(store.get("exp-3"), record)

    def test_key_adoption_over_unsigned_chain_requires_rebuild(self):
        # Entries written before the custodian key existed are unsigned,
        # not forged — but they cannot verify, so adopting chain_key
        # mid-stream is an explicit rebuild decision, not a backfill.
        store = MemoryStore(self.db)
        store.ingest(_v1_record())
        store.close()
        store = MemoryStore(self.db, chain_key=(self.seed, "exp-key-1"))
        self.addCleanup(store.close)
        self.assertFalse(store.verify_chain())
        self.assertEqual(store.last_chain_failure, "unsigned_entries")
        with self.assertRaisesRegex(MemoryError, "chain_corrupt"):
            store.repair_chain()
        self.assertEqual(store.repair_chain(rebuild=True), 1)
        self.assertTrue(store.verify_chain())

    def test_repair_refuses_corrupt_without_rebuild(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys,
                            chain_key=(self.seed, "exp-key-1"))
        self.addCleanup(store.close)
        store.ingest(_v2_record(self.seed))
        store.ingest(_v2_record(self.seed, experience_id="exp-2",
                                episode_id="ep-2"))
        store._conn().execute("DELETE FROM memory_chain WHERE seq=1")
        with self.assertRaisesRegex(MemoryError, "chain_corrupt"):
            store.repair_chain()
        self.assertEqual(store.repair_chain(rebuild=True), 2)
        self.assertTrue(store.verify_chain())
        self.assertEqual(store.get("exp-1"), _v2_record(self.seed))

    def test_malformed_chain_signature_fails_closed(self):
        store = MemoryStore(self.db, trusted_signer_keys=self.keys,
                            chain_key=(self.seed, "exp-key-1"))
        self.addCleanup(store.close)
        store.ingest(_v2_record(self.seed))
        store._conn().execute(
            "UPDATE memory_chain SET signature='zz' WHERE seq=1")
        self.assertFalse(store.verify_chain())
        self.assertEqual(store.last_chain_failure, "signature_malformed")
        with self.assertRaisesRegex(MemoryError, "chain_invalid"):
            store.get("exp-1")

    def test_chain_key_only_store_verifies_reads(self):
        # Chain custody without record trust: V1 ingests stay allowed but
        # a tampered chain still fails closed on read.
        store = MemoryStore(self.db, chain_key=(self.seed, "exp-key-1"))
        self.addCleanup(store.close)
        store.ingest(_v1_record())
        store._conn().execute(
            "UPDATE memory_chain SET head=? WHERE seq=1", ("f" * 64,))
        with self.assertRaisesRegex(MemoryError, "chain_invalid"):
            store.get("exp-1")
        self.assertEqual(store.last_chain_failure,
                         "head_recompute_mismatch")


class IssuanceTests(unittest.TestCase):
    """Issuance pins protocol identity; caller fields cannot override."""

    def test_schema_version_pinned(self):
        from sis.v3.memory import (
            issue_experience_record, verify_experience_signature)
        seed, public = signatures.generate_keypair()
        base = _v1_record().to_dict()
        base.pop("schema_version")
        record = issue_experience_record(
            seed, "exp-key-1", **base,
            task_id="task-A", attempt_id="att-1",
            repo_snapshot_digest="d" * 64,
            execution_receipt_digest="e" * 64,
            schema_version=99)
        self.assertEqual(record.to_dict()["schema_version"], 1)
        self.assertTrue(
            verify_experience_signature(record, public.hex()))


class SearchStarvationTests(unittest.TestCase):
    """T4: representable rules must not starve on late features."""

    def _study(self, seed=0, features=16, train_n=6, val_n=3):
        rng = random.Random(seed)
        names = [f"x{i}" for i in range(features)]
        seen = set()
        rows = []
        while len(rows) < train_n + val_n:
            inputs = {name: rng.randint(0, 9) for name in names}
            key = tuple(inputs[n] for n in names)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "inputs": inputs,
                "output": inputs["x14"] * inputs["x15"] + 2})
        return rows[:train_n], rows[train_n:]

    def test_late_feature_rule_within_budget(self):
        from sis.induction import induce
        from sis.expression import evaluate
        train, validation = self._study()
        result = induce(train, validation, max_candidates=50000)
        self.assertIsNotNone(result["rule"], result["status"])
        self.assertEqual(
            result["validation_passed"], len(validation), result["status"])
        # The recovered rule must generalize to unseen oracle points.
        rng = random.Random(1)
        for _ in range(10):
            inputs = {f"x{i}": rng.randint(0, 9) for i in range(16)}
            self.assertEqual(
                evaluate(result["rule"], inputs),
                inputs["x14"] * inputs["x15"] + 2)

    def test_two_feature_analogue_still_found(self):
        from sis.induction import induce
        train = [
            {"inputs": {"x0": a, "x1": b}, "output": a * b + 2}
            for a, b in ((1, 2), (3, 4), (5, 6), (2, 7), (0, 3), (4, 4))]
        validation = [
            {"inputs": {"x0": 2, "x1": 5}, "output": 12},
            {"inputs": {"x0": 6, "x1": 1}, "output": 8}]
        result = induce(train, validation, max_candidates=12000)
        self.assertIsNotNone(result["rule"], result["status"])
        self.assertEqual(result["validation_passed"], 2, result["status"])


class ReleaseIdentityTests(unittest.TestCase):
    """T5: release/ provenance must describe the source it ships."""

    def test_release_inventory_matches_current_manifest(self):
        manifest = json.loads(
            (ROOT / "RELEASE_SHA256.json").read_text())["files"]
        inventory = json.loads(
            (ROOT / "release" / "source_inventory.json").read_text())
        self.assertEqual(
            set(inventory["files"]), set(manifest),
            "release source_inventory covers a different file set")
        for relative, digest in manifest.items():
            self.assertEqual(
                inventory["files"][relative]["sha256"], digest,
                f"release inventory hash drifted at {relative}")

    def test_release_commit_covers_current_source(self):
        release = json.loads(
            (ROOT / "release" / "release_manifest.json").read_text())
        commit = release["source_commit"]
        subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-e", f"{commit}^{{commit}}"],
            check=True, capture_output=True)
        head = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"]).decode().strip()
        manifest = json.loads(
            (ROOT / "RELEASE_SHA256.json").read_text())["files"]
        changed = subprocess.check_output(
            ["git", "-C", str(ROOT), "diff", "--name-only",
             commit, head, "--", *sorted(manifest)]).decode().split()
        self.assertEqual(
            changed, [],
            "release source_commit predates manifest-covered changes "
            f"{changed[:5]}")


if __name__ == "__main__":
    unittest.main()
