"""SIS v3.3.4 Phase 2 production-isolation regressions (gate G2).

Covers the audited gaps:

- G2.1: a production isolation policy is mandatory and every property —
  backend allowlist, trusted signer, policy/image digests, containment
  properties, freshness, and receipt/command/tree/worker binding — is
  required. Omitted arguments are no longer "no constraint".
- G2.2: production classification accepts only a typed
  ``IsolationVerification`` for the exact receipt, never a boolean.
- G2.3: new production evaluations issue ``OutcomeReceiptV2`` binding
  the execution, attestation, runtime, protocol, worker and sandbox
  policy digests; V1 remains readable for historical evidence.
- G2.5: attestation reuse, wrong workers, missing properties, and the
  local backend's self-reported marker all fail closed.

Executor-level red-team cases (symlink escape, network, environment,
fork limits, resource exhaustion) live in ``test_runner_isolation.py``.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sis.v3 import signatures
from sis.v3.contracts import ContractError, TaskEnvelopeV1
from sis.v3.evaluation_runtime import (
    SANDBOX_FAILURE,
    TASK_FAIL,
    TASK_PASS,
    TIMEOUT,
    classify_execution,
)
from sis.v3.isolation import (
    IsolationVerification,
    ProductionIsolationPolicy,
    issue_attestation,
    issue_attestation_for_receipt,
    verify_isolation_attestation,
    verify_production_isolation,
)
from sis.v3.runner import CommandSpec, LocalSubprocessExecutor
from sis.v3.verifier import (
    EvaluationRejected,
    JournalIntegrityError,
    OutcomeVerifier,
)
from sis.v3.contracts import OutcomeReceiptV1, OutcomeReceiptV2

from tests.v3.isolation_testkit import ScriptedExecutor

PY = sys.executable
ACCEPTANCE = b"import calc\nassert calc.scale(3, 4) == 12\nprint('ok')\n"
NOW = datetime.now(timezone.utc).isoformat(
    timespec="seconds").replace("+00:00", "Z")
FUTURE = "2027-01-01T00:00:00Z"
PAST = "2026-01-01T00:00:00Z"


def _task(task_id="task-scale", isolation_profile="worker_microvm"):
    return TaskEnvelopeV1(
        schema_version=1, task_id=task_id,
        repo_snapshot_digest="0" * 64, base_commit=None,
        task_statement_digest="1" * 64,
        permitted_commands=("run-tests",),
        isolation_profile=isolation_profile,
        time_budget_seconds=300, token_budget=10_000, tool_budget=50,
        actor_id="agent-1", evaluator_task_ref=task_id,
    )


class IsolationFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "README.txt").write_text("fixture\n")
        self.seed, self.public = signatures.generate_keypair()
        self.executor = ScriptedExecutor(
            self.root / "exec", worker_identity="worker-A")
        workspace = self.executor.prepare(self.base)
        self.spec = CommandSpec(
            argv=(sys.executable, "-c", "print(1)"))
        self.receipt = self.executor.run(workspace, self.spec)

    def policy(self, **overrides):
        fields = dict(
            allowed_backends=frozenset({"linux-rootless-worker"}),
            trusted_keys={"isolator-1": self.public.hex()},
            required_policy_digest="aa" * 32,
            required_image_digest="bb" * 32,
            required_properties=frozenset({
                "fs:workspace_confined", "net:denied", "proc:namespaced"}),
        )
        fields.update(overrides)
        return ProductionIsolationPolicy(**fields)

    def issue(self, receipt=None, seed=None, key_id="isolator-1", **overrides):
        receipt = receipt or self.receipt
        fields = dict(
            backend="linux-rootless-worker",
            worker_identity="worker-A",
            policy_digest="aa" * 32,
            image_digest="bb" * 32,
            command_spec_digest=receipt.command_spec_digest,
            workspace_input_digest=receipt.before_tree_digest,
            execution_receipt_digest=receipt.digest,
            properties=("fs:workspace_confined", "net:denied",
                        "proc:namespaced"),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        fields.update(overrides)
        return issue_attestation(seed or self.seed, key_id, **fields)

    def verify(self, attestation, receipt=None, policy=None, **kw):
        return verify_production_isolation(
            attestation, receipt or self.receipt,
            policy or self.policy(), **kw)


class PolicyValidationTests(IsolationFixture):
    """G2.1: a permissive policy cannot be constructed."""

    def test_each_required_field_is_enforced(self):
        for overrides in (
                {"allowed_backends": frozenset()},
                {"trusted_keys": {}},
                {"trusted_keys": {"isolator-1": "not-hex"}},
                {"trusted_keys": {"isolator-1": "00" * 32}},
                {"required_policy_digest": "short"},
                {"required_image_digest": "zz" * 32},
                {"required_properties": frozenset()},
                {"require_expiry": "yes"},
                {"max_attestation_age_seconds": 0},
        ):
            with self.subTest(**{k: str(v)[:20] for k, v in overrides.items()}):
                with self.assertRaises(ContractError):
                    self.policy(**overrides)

    def test_policy_digest_binds_allowlist_and_properties(self):
        base = self.policy()
        self.assertNotEqual(
            base.digest,
            self.policy(allowed_backends=frozenset({"microvm"})).digest)
        self.assertNotEqual(
            base.digest,
            self.policy(required_properties=frozenset({
                "fs:workspace_confined", "net:denied"})).digest)

    def test_trusted_keys_are_immutable(self):
        policy = self.policy()
        with self.assertRaises(TypeError):
            policy.trusted_keys["isolator-1"] = "00" * 32


class ProductionVerificationTests(IsolationFixture):
    """G2.1: every mandatory property is checked, or verification fails."""

    def test_correctly_bound_attestation_verifies(self):
        verdict = self.verify(self.issue())
        self.assertTrue(verdict.ok, verdict.reason)
        self.assertEqual(verdict.receipt_digest, self.receipt.digest)
        self.assertEqual(verdict.backend, "linux-rootless-worker")
        self.assertEqual(verdict.worker_identity, "worker-A")
        self.assertEqual(
            verdict.verified_properties,
            ("fs:workspace_confined", "net:denied", "proc:namespaced"))
        self.assertEqual(verdict.signer_key_id, "isolator-1")

    def test_missing_containment_property_rejected(self):
        attestation = self.issue(properties=("fs:workspace_confined",))
        verdict = self.verify(attestation)
        self.assertFalse(verdict.ok)
        self.assertIn("missing_property", verdict.reason)

    def test_network_property_cannot_be_omitted(self):
        attestation = self.issue(
            properties=("fs:workspace_confined", "proc:namespaced"))
        verdict = self.verify(attestation)
        self.assertEqual(verdict.reason, "missing_property:net:denied")

    def test_wrong_image_rejected(self):
        self.assertEqual(
            self.verify(self.issue(image_digest="cc" * 32)).reason,
            "image_mismatch")

    def test_wrong_policy_rejected(self):
        self.assertEqual(
            self.verify(self.issue(policy_digest="cc" * 32)).reason,
            "policy_mismatch")

    def test_unallowlisted_backend_rejected(self):
        self.assertEqual(
            self.verify(self.issue(backend="local-subprocess")).reason,
            "backend_not_allowed")

    def test_untrusted_signer_rejected(self):
        other_seed, _public = signatures.generate_keypair()
        self.assertEqual(
            self.verify(self.issue(
                seed=other_seed, key_id="isolator-unknown")).reason,
            "untrusted_signer")
        self.assertEqual(
            self.verify(self.issue(key_id="isolator-unknown")).reason,
            "untrusted_signer")

    def test_expired_attestation_rejected(self):
        attestation = self.issue(
            issued_at="2026-11-09T12:00:00Z",
            expires_at="2026-11-09T12:30:00Z")
        self.assertEqual(
            self.verify(attestation, at_time="2026-11-09T13:00:00Z").reason,
            "attestation_expired")
        self.assertTrue(
            self.verify(attestation, at_time="2026-11-09T12:15:00Z").ok)

    def test_expiry_is_mandatory(self):
        self.assertEqual(
            self.verify(self.issue(expires_at=None)).reason,
            "attestation_has_no_expiry")

    def test_stale_attestation_rejected(self):
        attestation = self.issue(issued_at="2026-11-09T10:00:00Z")
        self.assertEqual(
            self.verify(attestation, at_time="2026-11-09T12:00:01Z").reason,
            "attestation_too_old")

    def test_future_attestation_rejected(self):
        attestation = self.issue(issued_at="2026-11-09T13:00:00Z")
        self.assertEqual(
            self.verify(attestation, at_time="2026-11-09T12:00:00Z").reason,
            "attestation_issued_in_future")

    def test_reused_attestation_for_other_receipt_rejected(self):
        workspace = self.executor.prepare(self.base)
        other = self.executor.run(workspace, CommandSpec(
            argv=(sys.executable, "-c", "print(2)")))
        attestation = self.issue(execution_receipt_digest=other.digest)
        self.assertEqual(self.verify(attestation).reason, "receipt_mismatch")

    def test_attestation_for_other_command_rejected(self):
        self.assertEqual(
            self.verify(self.issue(command_spec_digest="f" * 64)).reason,
            "command_mismatch")

    def test_attestation_for_other_workspace_rejected(self):
        self.assertEqual(
            self.verify(self.issue(workspace_input_digest="f" * 64)).reason,
            "workspace_mismatch")

    def test_attestation_for_other_worker_rejected(self):
        self.assertEqual(
            self.verify(self.issue(worker_identity="worker-B")).reason,
            "worker_mismatch")

    def test_forged_signature_rejected(self):
        attestation = self.issue()
        document = attestation.to_dict()
        document["properties"] = [
            "fs:workspace_confined", "net:denied", "proc:namespaced",
            "env:scrubbed"]
        from sis.v3.contracts import IsolationAttestationV1
        forged = IsolationAttestationV1.from_dict(document)
        self.assertEqual(self.verify(forged).reason, "signature_invalid")

    def test_malformed_attestation_rejected(self):
        self.assertEqual(
            self.verify({"not": "an attestation"}).reason,
            "attestation_malformed")

    def test_permissive_entry_point_delegates_to_policy(self):
        attestation = self.issue(properties=("fs:workspace_confined",))
        self.assertFalse(verify_isolation_attestation(
            attestation, self.receipt,
            trusted_keys={"isolator-1": self.public.hex()},
            policy=self.policy()))
        self.assertTrue(verify_isolation_attestation(
            self.issue(), self.receipt,
            trusted_keys={"isolator-1": self.public.hex()},
            policy=self.policy()))


class ProductionClassificationTests(IsolationFixture):
    """G2.2: only a typed verdict for this exact receipt can qualify."""

    def test_production_without_verification_is_sandbox_failure(self):
        receipt = self.receipt
        self.assertEqual(
            classify_execution(receipt, production=True), SANDBOX_FAILURE)

    def test_boolean_verification_is_not_accepted(self):
        self.assertEqual(
            classify_execution(
                self.receipt, production=True,
                isolation_verification=True),
            SANDBOX_FAILURE)

    def test_verification_for_other_receipt_is_sandbox_failure(self):
        verdict = IsolationVerification(
            ok=True, reason="ok", receipt_digest="f" * 64)
        self.assertEqual(
            classify_execution(
                self.receipt, production=True,
                isolation_verification=verdict),
            SANDBOX_FAILURE)

    def test_valid_verification_qualifies(self):
        verdict = self.verify(self.issue())
        self.assertEqual(
            classify_execution(
                self.receipt, production=True,
                isolation_verification=verdict),
            TASK_PASS)

    def test_local_marker_disqualifies_even_with_valid_verification(self):
        executor = ScriptedExecutor(
            self.root / "local-exec", worker_identity="worker-A",
            security_errors=("isolation:unverified_local",))
        workspace = executor.prepare(self.base)
        receipt = executor.run(workspace, self.spec)
        attestation = self.issue(receipt=receipt)
        verdict = verify_production_isolation(
            attestation, receipt, self.policy())
        self.assertTrue(verdict.ok, verdict.reason)
        self.assertEqual(
            classify_execution(
                receipt, production=True,
                isolation_verification=verdict),
            SANDBOX_FAILURE)

    def test_old_boolean_keyword_is_gone(self):
        with self.assertRaises(TypeError):
            classify_execution(
                self.receipt, production=True, isolation_attested=True)


class ProductionVerifierTests(unittest.TestCase):
    """G2.2/G2.3: the verifier issues V2 only with validated isolation."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.submission = self.root / "submission"
        self.submission.mkdir()
        (self.submission / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n", encoding="utf-8")
        self.isolator_seed, self.isolator_public = signatures.generate_keypair()
        self.policy = ProductionIsolationPolicy(
            allowed_backends=frozenset({"linux-rootless-worker"}),
            trusted_keys={"isolator-1": self.isolator_public.hex()},
            required_policy_digest="aa" * 32,
            required_image_digest="bb" * 32,
            required_properties=frozenset({
                "fs:workspace_confined", "net:denied", "proc:namespaced"}),
        )
        self.executor = ScriptedExecutor(
            self.root / "exec", worker_identity="worker-A")
        self.verifier = OutcomeVerifier(
            executor=self.executor,
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
            isolation_policy=self.policy)
        self.verifier.register_task(
            actor_role="evaluator", task_id="task-scale",
            criterion_version="acceptance-v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE})
        self.executions = []

    def resolver(self, receipt, **overrides):
        self.executions.append(receipt)
        fields = dict(
            backend="linux-rootless-worker",
            worker_identity=receipt.worker_identity,
            policy_digest="aa" * 32,
            image_digest="bb" * 32,
            command_spec_digest=receipt.command_spec_digest,
            workspace_input_digest=receipt.before_tree_digest,
            execution_receipt_digest=receipt.digest,
            properties=("fs:workspace_confined", "net:denied",
                        "proc:namespaced"),
            issued_at=NOW, expires_at=FUTURE,
        )
        fields.update(overrides)
        return issue_attestation(
            self.isolator_seed, "isolator-1", **fields)

    def evaluate(self, **kw):
        return self.verifier.evaluate(
            actor_role="evaluator", task=_task(),
            submission_dir=self.submission,
            evaluation_nonce=kw.pop("nonce", "nonce-1"), **kw)

    def test_production_evaluation_issues_v2(self):
        receipt = self.evaluate(isolation_attestation_resolver=self.resolver)
        self.assertIsInstance(receipt, OutcomeReceiptV2)
        self.assertEqual(receipt.outcome, "pass")
        self.assertEqual(
            receipt.execution_receipt_digest, self.executions[0].digest)
        self.assertEqual(receipt.worker_identity, "worker-A")
        self.assertEqual(receipt.sandbox_policy_digest, "aa" * 32)
        self.assertEqual(len(receipt.isolation_attestation_digest), 64)
        self.assertEqual(len(receipt.evaluator_runtime_digest), 64)
        self.assertEqual(len(receipt.evaluation_protocol_digest), 64)
        self.assertTrue(self.verifier.verify_receipt(receipt))
        loaded = self.verifier.load_receipt(receipt.digest)
        self.assertIsInstance(loaded, OutcomeReceiptV2)
        self.assertEqual(loaded.digest, receipt.digest)

    def test_production_requires_attestation(self):
        with self.assertRaisesRegex(
                EvaluationRejected, "isolation_attestation_required"):
            self.evaluate()

    def test_production_rejects_unverified_local_task_profile(self):
        with self.assertRaisesRegex(
                EvaluationRejected,
                "production_requires_qualified_task_profile"):
            self.verifier.evaluate(
                actor_role="evaluator",
                task=_task(isolation_profile="unverified_local"),
                submission_dir=self.submission,
                evaluation_nonce="nonce-profile",
                isolation_attestation_resolver=self.resolver)

    def test_production_rejects_invalid_attestation(self):
        def bad_resolver(receipt):
            return self.resolver(
                receipt, properties=("fs:workspace_confined",))

        with self.assertRaisesRegex(
                EvaluationRejected, "isolation_unverified.*missing_property"):
            self.evaluate(isolation_attestation_resolver=bad_resolver)

    def test_production_rejects_resolver_error(self):
        def broken(receipt):
            raise RuntimeError("isolator unavailable")

        with self.assertRaisesRegex(
                EvaluationRejected, "isolation_attestation_unavailable"):
            self.evaluate(isolation_attestation_resolver=broken)

    def test_production_rejects_reused_attestation(self):
        def reused(receipt):
            return self.resolver(
                receipt, execution_receipt_digest="f" * 64)

        with self.assertRaisesRegex(
                EvaluationRejected, "isolation_unverified.*receipt_mismatch"):
            self.evaluate(isolation_attestation_resolver=reused)

    def test_local_marker_produces_error_not_pass(self):
        executor = ScriptedExecutor(
            self.root / "local-exec", worker_identity="worker-A",
            security_errors=("isolation:unverified_local",))
        verifier = OutcomeVerifier(
            executor=executor, key_dir=self.root / "keys",
            registry_dir=self.root / "registry-local",
            isolation_policy=self.policy)
        verifier.register_task(
            actor_role="evaluator", task_id="task-scale",
            criterion_version="acceptance-v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE})
        receipt = verifier.evaluate(
            actor_role="evaluator", task=_task(),
            submission_dir=self.submission, evaluation_nonce="nonce-local",
            isolation_attestation_resolver=self.resolver)
        self.assertIsInstance(receipt, OutcomeReceiptV2)
        self.assertEqual(receipt.outcome, "error")

    def test_development_verifier_still_issues_v1(self):
        executor = ScriptedExecutor(self.root / "dev-exec")
        verifier = OutcomeVerifier(
            executor=executor, key_dir=self.root / "dev-keys",
            registry_dir=self.root / "dev-registry")
        verifier.register_task(
            actor_role="evaluator", task_id="task-scale",
            criterion_version="acceptance-v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE})
        receipt = verifier.evaluate(
            actor_role="evaluator", task=_task(),
            submission_dir=self.submission, evaluation_nonce="nonce-dev")
        self.assertIsInstance(receipt, OutcomeReceiptV1)
        self.assertTrue(verifier.verify_receipt(receipt))

    def test_v1_and_v2_coexist_after_restart(self):
        production = self.evaluate(isolation_attestation_resolver=self.resolver)
        dev_submission = self.root / "dev-submission"
        dev_submission.mkdir()
        (dev_submission / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n# dev\n", encoding="utf-8")
        development = OutcomeVerifier(
            executor=ScriptedExecutor(self.root / "dev-exec"),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry")
        development.register_task(
            actor_role="evaluator", task_id="task-scale",
            criterion_version="acceptance-v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE})
        v1 = development.evaluate(
            actor_role="evaluator", task=_task(),
            submission_dir=dev_submission, evaluation_nonce="nonce-v1")
        self.assertIsInstance(v1, OutcomeReceiptV1)
        restarted = OutcomeVerifier(
            executor=ScriptedExecutor(self.root / "restart-exec"),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
            isolation_policy=self.policy)
        self.assertIsInstance(
            restarted.load_receipt(v1.digest), OutcomeReceiptV1)
        self.assertIsInstance(
            restarted.load_receipt(production.digest), OutcomeReceiptV2)
        self.assertTrue(restarted.verify_receipt(production))
        self.assertTrue(restarted.verify_receipt(v1))

        from sis.v3.contracts import parse_outcome_receipt
        self.assertIsInstance(
            parse_outcome_receipt(v1.to_dict()), OutcomeReceiptV1)
        self.assertIsInstance(
            parse_outcome_receipt(production.to_dict()), OutcomeReceiptV2)

    def test_downstream_modules_accept_v2_receipts(self):
        root = Path(__file__).resolve().parents[2] / "src" / "sis" / "v3"
        for name in ("scope_grants.py", "procedures.py"):
            source = (root / name).read_text(encoding="utf-8")
            self.assertNotIn(
                "isinstance(receipt, OutcomeReceiptV1)", source, name)
        for name in ("evaluator_worker.py", "authority_db.py"):
            source = (root / name).read_text(encoding="utf-8")
            self.assertIn("parse_outcome_receipt", source, name)
            self.assertNotIn("OutcomeReceiptV1.from_json", source, name)


class AttestationIssuanceTests(IsolationFixture):
    """G2.4: the isolator can issue receipt-bound evidence, and only that."""

    def test_issuer_binds_receipt_and_verifies(self):
        attestation = issue_attestation_for_receipt(
            self.receipt, self.seed, "isolator-1",
            backend="linux-rootless-worker",
            policy_digest="aa" * 32,
            image_digest="bb" * 32,
            properties=("fs:workspace_confined", "net:denied",
                        "proc:namespaced"),
            issued_at=NOW, expires_at=FUTURE)
        self.assertEqual(
            attestation.execution_receipt_digest, self.receipt.digest)
        self.assertEqual(attestation.worker_identity, "worker-A")
        self.assertTrue(self.verify(attestation).ok)

    def test_issuer_refuses_local_execution(self):
        executor = ScriptedExecutor(
            self.root / "local", worker_identity="worker-A",
            security_errors=("isolation:unverified_local",))
        workspace = executor.prepare(self.base)
        receipt = executor.run(workspace, self.spec)
        with self.assertRaisesRegex(
                ContractError, "cannot_attest_unverified_local_execution"):
            issue_attestation_for_receipt(
                receipt, self.seed, "isolator-1",
                backend="linux-rootless-worker",
                policy_digest="aa" * 32, image_digest="bb" * 32,
                properties=("net:denied",),
                issued_at=NOW, expires_at=FUTURE)

    def test_issuer_requires_a_property(self):
        with self.assertRaisesRegex(ContractError, "properties"):
            issue_attestation_for_receipt(
                self.receipt, self.seed, "isolator-1",
                backend="linux-rootless-worker",
                policy_digest="aa" * 32, image_digest="bb" * 32,
                properties=())

    def _seed_file(self):
        import os
        seed_dir = self.root / "isolator"
        seed_dir.mkdir(mode=0o700, exist_ok=True)
        path = seed_dir / "isolator.seed"
        path.write_text(self.seed.hex(), encoding="ascii")
        os.chmod(path, 0o600)
        return path

    def _cli(self, **overrides):
        from tools.issue_worker_attestation import main
        receipt_path = self.root / "receipt.json"
        receipt_path.write_bytes(self.receipt.canonical_bytes())
        args = {
            "receipt": str(receipt_path),
            "seed": None,
            "output": str(self.root / "attestation.json"),
        }
        args.update(overrides)
        if args["seed"] is None:
            args["seed"] = str(self._seed_file())
        argv = [
            "--receipt", args["receipt"], "--seed-file", args["seed"],
            "--backend", "linux-rootless-worker",
            "--policy-digest", "aa" * 32, "--image-digest", "bb" * 32,
            "--property", "fs:workspace_confined",
            "--property", "net:denied", "--property", "proc:namespaced",
            "--issued-at", NOW, "--expires-in", "300",
            "--output", args["output"],
        ]
        return main(argv)

    def test_cli_writes_a_verifiable_attestation(self):
        from sis.v3.contracts import IsolationAttestationV1
        self.assertEqual(self._cli(), 0)
        path = self.root / "attestation.json"
        attestation = IsolationAttestationV1.from_json(path.read_bytes())
        self.assertTrue(self.verify(attestation).ok)

    def test_cli_refuses_overwrite_without_force(self):
        self.assertEqual(self._cli(), 0)
        with self.assertRaises(SystemExit):
            self._cli()

    def test_cli_rejects_public_seed(self):
        import os
        seed_path = self._seed_file()
        os.chmod(seed_path, 0o644)
        self.assertEqual(self._cli(seed=str(seed_path)), 1)
        self.assertFalse((self.root / "attestation.json").exists())

    def test_cli_rejects_malformed_receipt(self):
        bad = self.root / "bad-receipt.json"
        bad.write_bytes(b"{not-json")
        self.assertEqual(
            self._cli(receipt=str(bad)), 1)


class LocalBackendRedTeamTests(unittest.TestCase):
    """G2.5: the development backend can never mint production evidence."""

    def test_local_executor_receipt_is_never_production_qualified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            base.mkdir()
            (base / "README.txt").write_text("fixture\n")
            executor = LocalSubprocessExecutor(
                root / "exec", use_seatbelt=False, worker_identity="worker-A")
            workspace = executor.prepare(base)
            receipt = executor.run(workspace, CommandSpec(
                argv=(sys.executable, "-c", "print(1)")))
            self.assertIn("isolation:unverified_local", receipt.security_errors)
            self.assertNotIn("isolation:verified", receipt.security_errors)
            self.assertEqual(
                classify_execution(receipt, production=True),
                SANDBOX_FAILURE)


if __name__ == "__main__":
    unittest.main()
