"""Signed sandbox policy == the ``docker run`` argv actually launched (C1/C2).

The Docker CLI is replaced by a recording fake, so these tests need no
daemon: they check that the policy document an isolator signs is derived
from the same flags the executor passes to ``docker run``, that gVisor and
the allowlist seccomp profile are mandatory for the production backend,
and that the committed seccomp profile keeps its invariants.
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import derive_sandbox_seccomp  # noqa: E402
import qualify_docker_isolation as gate2  # noqa: E402
from sis.v3 import signatures  # noqa: E402
from sis.v3.contracts import ContractError  # noqa: E402
from sis.v3.docker_sandbox import (LAUNCH_PLACEHOLDERS,  # noqa: E402
                                   PRODUCTION_PROPERTIES,
                                   DockerSandboxExecutor,
                                   policy_document_digest,
                                   production_isolation_policy,
                                   render_launch_flags)
from sis.v3.isolation import (issue_attestation_for_receipt,  # noqa: E402
                              verify_production_isolation)
from sis.v3.runner import CommandSpec, ResourceLimits  # noqa: E402

SECCOMP = ROOT / "docker" / "sandbox" / "seccomp.json"
IMAGE = "sis-evaluator:3.3.9@sha256:" + "a" * 64

FAKE_DOCKER = r'''#!{python}
import json, sys
argv = sys.argv[1:]
with open({log!r}, "a") as handle:
    handle.write(json.dumps(argv) + "\n")
if argv[:1] == ["inspect"]:
    print("true")
elif argv[:1] == ["image"]:
    print("sha256:" + "b" * 64)
elif argv[:1] == ["exec"] and argv[-6:] == ["tar", "-C", "/workspace", "-cf", "-", "."]:
    sys.stdout.buffer.write(open({payload!r}, "rb").read())
elif argv[:1] == ["exec"] and "-c" in argv and argv[-1].startswith("print("):
    print("qualified")
sys.exit(0)
'''


def _executor(root: Path, **overrides) -> DockerSandboxExecutor:
    options = {
        "image": IMAGE, "production": True, "runtime": "runsc",
        "seccomp_profile": SECCOMP, "user": "1000:1000",
        "image_id": "b" * 64,
    }
    options.update(overrides)
    with mock.patch.object(DockerSandboxExecutor, "_require_docker",
                           return_value="test-server"):
        return DockerSandboxExecutor(root / "exec", **options)


class ProductionConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_production_requires_gvisor(self):
        for runtime in (None, "runc"):
            with self.subTest(runtime=runtime):
                with self.assertRaisesRegex(
                        ContractError, "production_requires_gvisor_runtime"):
                    _executor(self.root, runtime=runtime)

    def test_production_requires_a_seccomp_profile(self):
        with self.assertRaisesRegex(
                ContractError, "production_requires_seccomp_profile"):
            _executor(self.root, seccomp_profile=None)

    def test_unknown_runtime_is_refused(self):
        with self.assertRaises(ContractError):
            _executor(self.root, production=False, runtime="kata")

    def test_a_denylist_profile_is_refused(self):
        profile = self.root / "denylist.json"
        profile.write_text(json.dumps({
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [{"names": ["ptrace"], "action": "SCMP_ACT_ERRNO"}]}))
        with self.assertRaisesRegex(
                ContractError, "seccomp_profile_must_deny_by_default"):
            _executor(self.root, seccomp_profile=profile)

    def test_the_executor_launches_from_a_private_profile_copy(self):
        executor = _executor(self.root)
        copy = executor._seccomp_path
        self.assertTrue(copy.is_relative_to(executor.root))
        self.assertEqual(copy.read_bytes(), SECCOMP.read_bytes())
        self.assertEqual(executor.seccomp_profile_sha256,
                         hashlib.sha256(SECCOMP.read_bytes()).hexdigest())


class PolicyRoundTripTests(unittest.TestCase):
    """The policy digest names exactly the controls ``docker run`` got."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "docker.jsonl"
        self.payload = self.root / "payload.tar"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            data = b"seed"
            info = tarfile.TarInfo("./seed.txt")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        self.payload.write_bytes(buffer.getvalue())
        self.fake = self.root / "fake-docker"
        self.fake.write_text(FAKE_DOCKER.format(
            python=sys.executable, log=str(self.log),
            payload=str(self.payload)))
        self.fake.chmod(0o755)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "seed.txt").write_text("seed")

    def calls(self) -> list[list[str]]:
        return [json.loads(line)
                for line in self.log.read_text().splitlines()]

    def run_once(self, executor, limits=None):
        workspace = executor.prepare(self.base)
        try:
            return executor.run(workspace, CommandSpec(
                argv=("python3", "-c", "print('qualified')"),
                limits=limits or ResourceLimits(
                    wall_seconds=60, process_count=64)))
        finally:
            executor.destroy(workspace)

    def launched_flags(self, executor) -> list[str]:
        runs = [call for call in self.calls() if call[:1] == ["run"]]
        self.assertEqual(len(runs), 1, runs)
        argv = runs[0]
        start = argv.index("--label") + 2
        end = argv.index("--mount")
        self.assertEqual(argv[start - 2:start], [
            "--label", f"sis.v3.sandbox={executor.worker_identity}"])
        return argv[start:end]

    @staticmethod
    def values_from_receipt(receipt, executor) -> dict:
        """Recover the per-run values from the receipt's own markers."""
        markers = {}
        for marker in receipt.security_errors:
            parts = marker.split(":")
            if parts[0] == "docker" and len(parts) >= 3:
                markers[parts[1]] = ":".join(parts[2:])
        uid, gid = markers["user"].split(":")
        return {
            "memory_bytes": markers["memory_bytes"],
            "pids_limit": markers["pids_limit"],
            "disk_bytes": markers["disk_bytes"],
            "cpu_seconds": markers["ulimit_cpu"],
            "uid": uid, "gid": gid,
            "workspace_mode": "0770",
            "seccomp_profile": str(executor._seccomp_path),
        }

    def test_signed_policy_equals_the_launched_argv(self):
        executor = _executor(self.root, docker_binary=str(self.fake))
        receipt = self.run_once(executor)
        policy = executor.launch_policy()
        launched = self.launched_flags(executor)
        self.assertEqual(
            render_launch_flags(policy, self.values_from_receipt(
                receipt, executor)),
            launched)
        # The receipt names the digest of that same policy, and the
        # digest is a pure function of the document written as policy.json.
        self.assertIn(f"docker:policy:{executor.policy_digest()}",
                      receipt.security_errors)
        self.assertEqual(policy_document_digest(
            json.loads(json.dumps(policy))), executor.policy_digest())

    def test_launch_carries_gvisor_seccomp_and_the_kept_protections(self):
        executor = _executor(self.root, docker_binary=str(self.fake))
        self.run_once(executor)
        flags = self.launched_flags(executor)
        pairs = list(zip(flags, flags[1:]))
        self.assertIn(("--runtime", "runsc"), pairs)
        self.assertIn(("--network", "none"), pairs)
        self.assertIn(("--cap-drop", "ALL"), pairs)
        self.assertIn(("--security-opt", "no-new-privileges"), pairs)
        self.assertIn("--read-only", flags)
        seccomp = [value for flag, value in pairs
                   if flag == "--security-opt"
                   and value.startswith("seccomp=")]
        self.assertEqual(len(seccomp), 1)
        path = Path(seccomp[0].removeprefix("seccomp="))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         executor.launch_policy()["seccomp_profile_sha256"])
        self.assertNotIn("0", flags[flags.index("--user") + 1].split(":"))

    def test_per_run_values_never_exceed_the_policy_ceilings(self):
        executor = _executor(self.root, docker_binary=str(self.fake),
                             pids_limit=64)
        receipt = self.run_once(executor, ResourceLimits(
            wall_seconds=60, process_count=128))
        ceilings = executor.launch_policy()["ceilings"]
        values = self.values_from_receipt(receipt, executor)
        self.assertLessEqual(int(values["pids_limit"]), ceilings["pids_limit"])
        self.assertLessEqual(int(values["memory_bytes"]),
                             ceilings["memory_bytes"])

    def test_the_policy_template_has_no_host_specific_values(self):
        first = _executor(self.root / "a", user="1000:1000").launch_policy()
        second = _executor(self.root / "b", user="1234:1234").launch_policy()
        self.assertEqual(first, second)
        self.assertIn(LAUNCH_PLACEHOLDERS["seccomp_profile"],
                      " ".join(first["launch_flags"]))
        self.assertNotIn(str(self.root), json.dumps(first))

    def test_policy_digest_binds_runtime_image_and_profile(self):
        production = _executor(self.root / "p").policy_digest()
        runc = _executor(self.root / "r", production=False,
                         runtime="runc").policy_digest()
        other_image = _executor(
            self.root / "i", image="sis-evaluator@sha256:" + "c" * 64
        ).policy_digest()
        profile = self.root / "other.json"
        document = json.loads(SECCOMP.read_text())
        document["syscalls"] = document["syscalls"][:-1]
        profile.write_text(json.dumps(document))
        other_profile = _executor(
            self.root / "s", seccomp_profile=profile).policy_digest()
        self.assertEqual(len({production, runc, other_image,
                              other_profile}), 4)

    def test_qualification_claims_gvisor_only_for_a_runsc_launch(self):
        executor = _executor(self.root / "q", docker_binary=str(self.fake))
        receipt = self.run_once(executor)
        self.assertEqual(gate2.claimable_properties(receipt, executor),
                         PRODUCTION_PROPERTIES)
        runc = _executor(self.root / "rr", production=False, runtime="runc",
                         docker_binary=str(self.fake))
        self.log.unlink()
        receipt = self.run_once(runc)
        claims = gate2.claimable_properties(receipt, runc)
        self.assertNotIn("kernel:gvisor", claims)
        # The production policy then refuses the attestation.
        seed, public = signatures.generate_keypair()
        attestation = issue_attestation_for_receipt(
            receipt, seed, "k", backend="docker_sandbox",
            policy_digest=runc.policy_digest(), image_digest="a" * 64,
            properties=claims)
        result = verify_production_isolation(
            attestation, receipt, production_isolation_policy(
                trusted_keys={"k": public.hex()}, image_digest="a" * 64,
                policy_digest=runc.policy_digest()))
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "missing_property:kernel:gvisor")

    def test_qualification_tool_signs_the_launch_policy(self):
        output = self.root / "evidence"
        with mock.patch.object(DockerSandboxExecutor, "_require_docker",
                               return_value="test-server"), \
                mock.patch.object(DockerSandboxExecutor, "__init__",
                                  _patched_init(str(self.fake))):
            code = gate2.main(["--image", IMAGE, "--output", str(output)])
        record = json.loads((output / "qualification.json").read_text())
        self.assertEqual(code, 0, record)
        policy = json.loads((output / "policy.json").read_text())
        self.assertEqual(policy_document_digest(policy),
                         record["policy_digest"])
        self.assertTrue(record["policy_bound_to_receipt"])
        self.assertIn("kernel:gvisor", record["claimed_properties"])
        self.assertEqual(record["runtime"], "runsc")
        launched = self.launched_flags(_StubIdentity())
        self.assertIn("--runtime", launched)


class _StubIdentity:
    worker_identity = "docker-sandbox-v1"


def _patched_init(docker_binary):
    original = DockerSandboxExecutor.__init__

    def init(self, *args, **kwargs):
        kwargs["docker_binary"] = docker_binary
        kwargs.setdefault("image_id", "b" * 64)
        original(self, *args, **kwargs)
    return init


class SeccompProfileTests(unittest.TestCase):
    def test_committed_profile_keeps_its_invariants(self):
        profile = json.loads(SECCOMP.read_text())
        self.assertEqual(derive_sandbox_seccomp.check_invariants(profile), [])
        self.assertEqual(derive_sandbox_seccomp.main([]), 0)

    def test_dangerous_syscalls_are_not_allowed(self):
        allowed = derive_sandbox_seccomp.allowed_names(
            json.loads(SECCOMP.read_text()))
        for name in ("ptrace", "mount", "unshare", "setns", "bpf",
                     "keyctl", "process_vm_readv", "open_by_handle_at",
                     "io_uring_setup", "socketcall", "setuid"):
            self.assertNotIn(name, allowed)
        for name in ("read", "write", "openat", "execve", "futex", "mmap",
                     "clone", "wait4", "socket", "pipe2", "getrandom"):
            self.assertIn(name, allowed)

    def test_profile_is_reproducible_from_the_pinned_upstream(self):
        # Re-deriving from the pinned upstream document must reproduce the
        # committed bytes. The upstream file is fetched only by maintainers;
        # here the derivation is replayed from the committed allowlist.
        profile = json.loads(SECCOMP.read_text())
        base = [rule for rule in profile["syscalls"]
                if rule.get("comment", "").startswith("Moby")][0]
        synthetic = {"syscalls": [
            {"names": sorted(set(base["names"])
                             | set(derive_sandbox_seccomp.REMOVED)),
             "action": "SCMP_ACT_ALLOW"},
            *[{"names": ["personality"], "action": "SCMP_ACT_ALLOW",
               "args": rule["args"]} for rule in profile["syscalls"]
              if rule.get("names") == ["personality"]],
        ]}
        self.assertEqual(derive_sandbox_seccomp.render(
            derive_sandbox_seccomp.derive(synthetic)), SECCOMP.read_bytes())


if __name__ == "__main__":
    unittest.main()
