"""Follow-up: the five-arm CLI configures trusted candidate authorities.

``--candidate-registry`` used to open the registry without evaluator or
operator keys, so the strict serving path failed closed and a learned
bundle was never served from the command line. ``--trust-config`` now
supplies the trust anchors in the ``sis.v3.bootstrap`` config format, a
registry without them is refused at argument parsing, and
``--record-unverified`` keeps the explicit recording-only mode.
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis.v3 import signatures
from tests.v3.candidate_testkit import CandidateStack
from tests.v3.test_candidates import make_candidate
from tests.v3.test_five_arm_real_run import (GIT, POSIX_CUSTODY,
                                             _learned_bundle, _manifest,
                                             _scripted_agent, _status, _write)
from tests.v3.test_five_arm_real_run import campaign_tool as tool

_PROTOCOL = {"name": "candidate-qualification", "alpha": 0.05,
             "arms": ["A", "E"]}


def _protocol_document(body=None) -> dict:
    from sis.v3.contracts import canonical_digest
    body = dict(body or _PROTOCOL)
    normalized = json.loads(json.dumps(body, sort_keys=True),
                            parse_float=lambda value: f"float:{value}")
    return {**body, "protocol_digest": canonical_digest(
        "eval_protocol", 1, normalized)}


def _trust(stack: CandidateStack, protocol) -> dict:
    return {
        "evaluator_keys": {stack.eval_key: stack.eval_public_hex},
        "operator_keys": {
            stack.op_key: signatures.public_key(stack.op_seed).hex()},
        "evaluation_protocol": protocol,
    }


def _qualified(stack: CandidateStack, cid: str, step: str):
    candidate = make_candidate(
        cid=cid, payload={"title": cid, "steps": [step]},
        scope={"kind": "global", "value": ""})
    stack.prepare(candidate)
    _, evidence, _ = stack.qualify(candidate)
    return candidate, evidence


class TrustConfigTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.protocol = _protocol_document()
        self.stack = CandidateStack(
            self.root / "candidates.db",
            protocol=self.protocol["protocol_digest"])
        self.addCleanup(self.stack.close)

    def _config(self, body) -> Path:
        path = self.root / "trust.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        return path

    def test_factory_re_authenticates_qualified_candidates(self):
        candidate, evidence = _qualified(self.stack, "cand-1", "Step one.")
        trust = tool.load_trust_config(
            self._config(_trust(self.stack, self.protocol)))
        self.assertEqual(trust["evaluation_protocol_digest"],
                         self.protocol["protocol_digest"])
        self.assertIsNone(trust["candidate_database"])
        factory = tool.trusted_registry_factory(trust)
        registry = factory(self.root / "candidates.db")
        try:
            basis = registry.serving_basis("cand-1")
            self.assertIn(evidence.digest, basis["evidence_refs"])
            self.assertEqual([c.candidate_id for c, _ in
                              registry.qualified_bases()], ["cand-1"])
        finally:
            registry.close()
        self.assertEqual(factory.trust_anchors, {
            "evaluator_key_ids": [self.stack.eval_key],
            "operator_key_ids": [self.stack.op_key],
            "evaluation_protocol_digest": self.protocol["protocol_digest"]})

    def test_wrong_keys_cannot_serve(self):
        _qualified(self.stack, "cand-1", "Step one.")
        other = CandidateStack(self.root / "other.db",
                               protocol=self.protocol["protocol_digest"])
        self.addCleanup(other.close)
        factory = tool.trusted_registry_factory(tool.load_trust_config(
            self._config(_trust(other, self.protocol))))
        registry = factory(self.root / "candidates.db")
        try:
            with self.assertRaises(RuntimeError):
                registry.serving_basis("cand-1")
        finally:
            registry.close()

    def test_bootstrap_config_with_protocol_file_is_accepted(self):
        (self.root / "conf").mkdir()
        (self.root / "conf" / "protocol.json").write_text(
            json.dumps(self.protocol), encoding="utf-8")
        body = _trust(self.stack, "protocol.json")
        body.update({"candidate_database": "../candidates.db",
                     "control_plane": "cp.sqlite",
                     "authority_epoch": 1})
        path = self.root / "conf" / "v3.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        trust = tool.load_trust_config(path)
        self.assertEqual(trust["evaluation_protocol_digest"],
                         self.protocol["protocol_digest"])
        self.assertEqual(trust["candidate_database"].resolve(),
                         (self.root / "candidates.db").resolve())

    def test_invalid_configs_fail_closed(self):
        good = _trust(self.stack, self.protocol)
        cases = {
            "trust_config_missing:operator_keys":
                {k: v for k, v in good.items() if k != "operator_keys"},
            "trust_config_invalid:evaluator_keys":
                {**good, "evaluator_keys": {"eval-x": "zz"}},
            "trust_config_invalid:operator_keys":
                {**good, "operator_keys": ["not", "a", "map"]},
            "trust_config_invalid:evaluation_protocol":
                {**good, "evaluation_protocol":
                    {**self.protocol, "alpha": 0.5}},
            "trust_config_unreadable:evaluation_protocol":
                {**good, "evaluation_protocol": "missing.json"},
        }
        for code, body in cases.items():
            with self.subTest(code=code):
                with self.assertRaises(tool.TrustConfigError) as raised:
                    tool.load_trust_config(self._config(body))
                self.assertEqual(str(raised.exception), code)
        with self.assertRaises(tool.TrustConfigError) as raised:
            tool.load_trust_config(self.root / "absent.json")
        self.assertTrue(str(raised.exception).startswith(
            "trust_config_unreadable"))


class CliOptionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.protocol = _protocol_document()
        self.stack = CandidateStack(
            self.root / "candidates.db",
            protocol=self.protocol["protocol_digest"])
        self.addCleanup(self.stack.close)
        self.trust_path = self.root / "trust.json"
        self.trust_path.write_text(
            json.dumps(_trust(self.stack, self.protocol)), encoding="utf-8")
        self.base = ["--real-agent", "--allow-local-executor",
                     "--manifest", str(self.root / "m.json"),
                     "-o", str(self.root / "out.json")]

    def _parse(self, *extra):
        """Run ``main`` with ``run_real`` captured; return its kwargs."""
        captured = {}

        def fake_run_real(output, manifest, **kwargs):
            captured.update(kwargs, output=output, manifest=manifest)
            return 0

        with mock.patch.object(tool, "run_real", fake_run_real):
            self.assertEqual(tool.main([*self.base, *extra]), 0)
        return captured

    def _error(self, *extra) -> str:
        stderr = io.StringIO()
        with mock.patch.object(tool, "run_real") as run_real, \
                contextlib.redirect_stderr(stderr), \
                self.assertRaises(SystemExit) as raised:
            tool.main([*self.base, *extra])
        self.assertEqual(raised.exception.code, 2)
        run_real.assert_not_called()
        return stderr.getvalue()

    def test_trust_config_builds_a_trusted_factory(self):
        kwargs = self._parse(
            "--guidance-bundle", str(self.root / "b.json"),
            "--candidate-registry", str(self.root / "candidates.db"),
            "--trust-config", str(self.trust_path))
        self.assertEqual(kwargs["candidate_registry"],
                         self.root / "candidates.db")
        factory = kwargs["registry_factory"]
        self.assertEqual(factory.trust_anchors["evaluator_key_ids"],
                         [self.stack.eval_key])
        self.assertEqual(factory.trust_anchors["operator_key_ids"],
                         [self.stack.op_key])
        _qualified(self.stack, "cand-1", "Step one.")
        registry = factory(kwargs["candidate_registry"])
        try:
            self.assertTrue(registry.serving_basis("cand-1")["evidence_refs"])
        finally:
            registry.close()

    def test_candidate_database_defaults_from_the_trust_config(self):
        body = json.loads(self.trust_path.read_text(encoding="utf-8"))
        body["candidate_database"] = "candidates.db"
        self.trust_path.write_text(json.dumps(body), encoding="utf-8")
        kwargs = self._parse("--guidance-bundle", str(self.root / "b.json"),
                             "--trust-config", str(self.trust_path))
        self.assertEqual(Path(kwargs["candidate_registry"]).resolve(),
                         (self.root / "candidates.db").resolve())

    def test_registry_without_trust_config_is_refused(self):
        message = self._error(
            "--guidance-bundle", str(self.root / "b.json"),
            "--candidate-registry", str(self.root / "candidates.db"))
        self.assertIn("--candidate-registry requires --trust-config", message)
        self.assertIn("--record-unverified", message)

    def test_invalid_trust_config_is_an_argument_error(self):
        self.trust_path.write_text(json.dumps({"evaluator_keys": {}}),
                                   encoding="utf-8")
        message = self._error(
            "--guidance-bundle", str(self.root / "b.json"),
            "--candidate-registry", str(self.root / "candidates.db"),
            "--trust-config", str(self.trust_path))
        self.assertIn("trust_config_missing:", message)

    def test_conflicting_or_incomplete_options_are_refused(self):
        self.assertIn("contradicts", self._error(
            "--guidance-bundle", str(self.root / "b.json"),
            "--trust-config", str(self.trust_path), "--record-unverified"))
        self.assertIn("requires --candidate-registry", self._error(
            "--guidance-bundle", str(self.root / "b.json"),
            "--trust-config", str(self.trust_path)))
        self.assertIn("requires --guidance-bundle", self._error(
            "--candidate-registry", str(self.root / "candidates.db"),
            "--trust-config", str(self.trust_path)))
        self.assertIn("requires --guidance-bundle",
                      self._error("--record-unverified"))

    def test_record_unverified_keeps_recording_only_mode(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            kwargs = self._parse(
                "--guidance-bundle", str(self.root / "b.json"),
                "--candidate-registry", str(self.root / "candidates.db"),
                "--record-unverified")
        self.assertIsNone(kwargs["candidate_registry"])
        self.assertIsNone(kwargs["registry_factory"])
        self.assertIn("learned_unverified", stderr.getvalue())
        # A bundle without a registry still needs no flag.
        kwargs = self._parse("--guidance-bundle", str(self.root / "b.json"))
        self.assertIsNone(kwargs["candidate_registry"])


@unittest.skipUnless(GIT and POSIX_CUSTODY,
                     "git and POSIX key custody are required")
class CliServingEndToEndTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name, value in (("codex_agent_status", _status),
                            ("_installed_codex_version",
                             lambda binary: "1.2.3"),
                            ("_codex_agent", _scripted_agent)):
            patcher = mock.patch.object(tool, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _study(self):
        document = _manifest(self.root)
        # The candidates' qualification protocol, distinct from the
        # study's own preregistered protocol.
        self.protocol = _protocol_document()
        stack = CandidateStack(
            self.root / "candidates.db",
            protocol=self.protocol["protocol_digest"])
        self.addCleanup(stack.close)
        qualified = {arm: _qualified(stack, f"candidate-{arm}",
                                     f"{arm} served step")
                     for arm in ("B", "C", "D")}
        # The bundle declares the qualification split the candidates'
        # receipts came from (induction repositories, never the holdout).
        bundle = _learned_bundle(
            document, receipts=list(stack.receipts.values()),
            signer=(stack.eval_key, stack.eval_public_hex))
        for arm in ("B", "C", "D"):
            candidate, evidence = qualified[arm]
            bundle["components"][arm][0].update({
                "candidate_digest": candidate.digest,
                "content_digest": candidate.content_digest,
                "evidence_digest": evidence.digest})
        bundle.pop("bundle_digest")
        bundle["bundle_digest"] = tool._bundle_digest(bundle)
        document["guidance_bundle_digest"] = bundle["bundle_digest"]
        manifest = _write(self.root, document)
        guidance = self.root / "guidance.json"
        guidance.write_text(json.dumps(bundle), encoding="utf-8")
        trust = self.root / "trust.json"
        trust.write_text(json.dumps(_trust(stack, self.protocol)),
                         encoding="utf-8")
        return stack, manifest, guidance, trust

    def _main(self, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return tool.main(list(args))

    def test_cli_serves_guidance_through_the_gateway(self):
        stack, manifest, guidance, trust = self._study()
        output = self.root / "report.json"
        self._main("--real-agent", "--allow-local-executor",
                   "--allow-shared-custody", "--manifest", str(manifest),
                   "--guidance-bundle", str(guidance),
                   "--candidate-registry", str(self.root / "candidates.db"),
                   "--trust-config", str(trust), "-o", str(output))
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertNotIn(report["release_gate"], (
            "BLOCKED_GUIDANCE", "BLOCKED_MANIFEST", "BLOCKED_CAMPAIGN"),
            report.get("note"))
        self.assertTrue(report["guidance"]["candidates_verified"])
        self.assertEqual(report["guidance"]["source"], "learned")
        self.assertEqual(report["guidance"]["routing"], "governed_serving")
        self.assertEqual(report["guidance"]["trust_anchors"], {
            "evaluator_key_ids": [stack.eval_key],
            "operator_key_ids": [stack.op_key],
            "evaluation_protocol_digest": self.protocol["protocol_digest"]})
        decisions = report["guidance"]["serving_decisions"]
        self.assertEqual({item["arm"] for item in decisions},
                         {"B", "C", "D", "E"})
        self.assertTrue(all(item["decision"] == "advisory"
                            and item["candidates"] for item in decisions))
        self.assertGreater(
            report["learning_qualification"]["decisive_contrast"]["wins"], 0)

    def test_cli_record_unverified_does_not_serve(self):
        _, manifest, guidance, _ = self._study()
        output = self.root / "report.json"
        with contextlib.redirect_stderr(io.StringIO()):
            self._main("--real-agent", "--allow-local-executor",
                       "--allow-shared-custody", "--manifest", str(manifest),
                       "--guidance-bundle", str(guidance),
                       "--candidate-registry",
                       str(self.root / "candidates.db"),
                       "--record-unverified", "-o", str(output))
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["guidance"]["source"], "learned_unverified")
        self.assertEqual(report["guidance"]["routing"], "static_bundle")
        self.assertIsNone(report["guidance"]["trust_anchors"])
        self.assertEqual(report["guidance"]["serving_decisions"], [])

    def test_run_real_without_a_trusted_factory_is_blocked(self):
        _, manifest, guidance, _ = self._study()
        output = self.root / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = tool.run_real(
                output, manifest, allow_shared_custody=True,
                guidance_path=guidance,
                candidate_registry=self.root / "candidates.db")
        self.assertEqual(code, 2)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["release_gate"], "BLOCKED_GUIDANCE")
        self.assertIn("candidate_registry_untrusted", report["note"])


if __name__ == "__main__":
    unittest.main()
