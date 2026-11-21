"""The agent principal: the coding agent runs as a separate OS user.

Most tests need no second user. ``AgentPrincipal`` takes a ``runner`` in
place of :func:`subprocess.Popen`; the tests either answer the helper
calls with canned results or run the real helper program as the current
user with the ``sudo -n -u NAME --`` prefix removed (never the ``kill``
operation, which would signal every process of the current user).

``AgentPrincipalIntegrationTests`` runs only when ``SIS_TEST_AGENT_USER``
names a second user that ``sudo -n -u USER /usr/bin/python3`` can become.
"""
from __future__ import annotations

import io
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sis.v3.adapters.claude_code import ClaudeCodeAdapter
from sis.v3.adapters.codex_cli import CodexCliAdapter
from sis.v3.agent_principal import (DEFAULT_PYTHON, HELPER_SOURCE,
                                    AgentPrincipal, AgentPrincipalError,
                                    receive_tree, sample_paths)
from sis.v3.benchmark import BudgetCaps, UsageMeter
from sis.v3.learning_qualification import (ClaudeCodeAgent, CodexCliAgent,
                                           claude_code_agent_status)
from sis.v3.runner import tree_digest

from .test_claude_code_adapter import standard_stream, write_fake_claude

POSIX = os.name == "posix"
ROOT = Path(__file__).resolve().parents[2]


class FakeProc:
    """A finished helper process with canned output."""

    def __init__(self, stdout: bytes = b"", returncode: int = 0,
                 stderr: bytes = b"") -> None:
        self.stdin = io.BytesIO()
        self.stdin.close = lambda: None
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = returncode
        self.pid = 999_999

    def communicate(self, data=None, timeout=None):
        if data:
            self.stdin.write(data)
        return self.stdout.getvalue(), self.stderr.getvalue()

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


class Recorder:
    """A runner that records every helper call and answers it."""

    def __init__(self, answers=None):
        self.calls: list[dict] = []
        self.answers = answers or {}

    def __call__(self, argv, **kwargs):
        op = argv[-1]
        answer = self.answers.get(op, {"ok": True})
        if callable(answer):
            answer = answer()
        if isinstance(answer, FakeProc):
            proc = answer
        else:
            proc = FakeProc(json.dumps(answer).encode() + b"\n")
        self.calls.append({"argv": list(argv), "kwargs": kwargs,
                           "op": op, "proc": proc})
        return proc

    def ops(self) -> list[str]:
        return [call["op"] for call in self.calls]


def unprivileged_uid() -> int:
    """A uid that is neither root nor the test process's own."""
    return os.geteuid() + 4242 if POSIX else 4242


def principal(home: str = "/home/sisagent", runner=None, **kwargs):
    kwargs.setdefault("uid", unprivileged_uid())
    kwargs.setdefault("gid", unprivileged_uid())
    return AgentPrincipal("sisagent", home=home, runner=runner, **kwargs)


def local_runner(tmp_kill=None):
    """Run the real helper as the current user (no sudo); fake ``kill``."""
    kills: list[int] = []

    def run(argv, **kwargs):
        if argv[-1] == "kill":
            kills.append(1)
            if tmp_kill is not None:
                tmp_kill()
            return FakeProc(b'{"ok": true, "rounds": 1}\n')
        assert argv[:5] == ["/usr/bin/sudo", "-n", "-u", "sisagent", "--"]
        command = [sys.executable] + argv[6:]
        return subprocess.Popen(command, **kwargs)
    run.kills = kills
    return run


def _ctx(workspace: Path, meter=None):
    return SimpleNamespace(
        task=SimpleNamespace(task_id="t1"), workspace=workspace,
        guidance=None, usage_meter=meter or UsageMeter(),
        budget=BudgetCaps(wall_seconds=60, token_budget=1_000_000,
                          tool_budget=100), supervisor=None)


@unittest.skipUnless(POSIX, "agent principals are POSIX-only")
class PrincipalIdentityTests(unittest.TestCase):
    def test_root_the_evaluator_and_odd_names_are_refused(self):
        with self.assertRaisesRegex(AgentPrincipalError, "root"):
            AgentPrincipal("sisagent", uid=0, gid=0, home="/root")
        if os.geteuid() != 0:
            with self.assertRaisesRegex(AgentPrincipalError, "evaluator"):
                AgentPrincipal("sisagent", uid=os.geteuid(), gid=0,
                               home="/home/x")
        for name in ("", "root;id", "-u", "a b", "../x", "A" * 40):
            with self.assertRaises(AgentPrincipalError):
                AgentPrincipal(name, uid=unprivileged_uid(), gid=1,
                               home="/home/x")
        with self.assertRaisesRegex(AgentPrincipalError, "does not exist"):
            AgentPrincipal.resolve("sis-no-such-user-x")

    def test_identity_and_provenance_name_the_user(self):
        agent = principal()
        self.assertEqual(agent.identity(), {
            "user": "sisagent", "uid": unprivileged_uid(),
            "mechanism": "sudo_helper_v1"})
        record = agent.describe()
        self.assertTrue(record["separated"])
        self.assertEqual(record["user"], "sisagent")
        self.assertEqual(record["evaluator_user"],
                         pwd.getpwuid(os.geteuid()).pw_name)

    def test_a_nologin_shell_becomes_sh(self):
        agent = principal(shell="/usr/sbin/nologin")
        self.assertEqual(agent.environment({})["SHELL"], "/bin/sh")


@unittest.skipUnless(POSIX, "agent principals are POSIX-only")
class LaunchTests(unittest.TestCase):
    def test_secrets_travel_over_stdin_not_argv(self):
        runner = Recorder({"exec": FakeProc()})
        agent = principal(runner=runner)
        env = {"ANTHROPIC_API_KEY": "sk-secret-value", "PATH": "/usr/bin"}
        agent.launch(["/opt/claude", "-p", "--", "fix it"],
                     cwd="/home/sisagent/sis-work/ws-1", env=env)
        call = runner.calls[0]
        argv = call["argv"]
        self.assertEqual(argv[:5], ["/usr/bin/sudo", "-n", "-u", "sisagent",
                                    "--"])
        self.assertEqual(argv[5:9], [DEFAULT_PYTHON, "-I", "-S", "-c"])
        self.assertEqual(argv[9:], [HELPER_SOURCE, "exec"])
        self.assertNotIn("sk-secret-value", " ".join(argv))
        # sudo runs with a minimal environment of its own, from "/", in a
        # new session (no controlling terminal, its own process group).
        self.assertNotIn("ANTHROPIC_API_KEY", call["kwargs"]["env"])
        self.assertEqual(call["kwargs"]["cwd"], "/")
        self.assertTrue(call["kwargs"]["start_new_session"])
        request = json.loads(call["proc"].stdin.getvalue())
        self.assertEqual(request["env"]["ANTHROPIC_API_KEY"],
                         "sk-secret-value")
        self.assertEqual(request["argv"][-1], "fix it")
        self.assertEqual(request["cwd"], "/home/sisagent/sis-work/ws-1")

    def test_environment_is_rehomed_to_the_agent_user(self):
        agent = principal()
        env = agent.environment({
            "HOME": "/home/sispilot", "USER": "sispilot",
            "LOGNAME": "sispilot", "TMPDIR": "/home/sispilot/tmp",
            "CLAUDE_CONFIG_DIR": "/home/sispilot/.claude",
            "CODEX_HOME": "/home/sisagent/.codex",
            "ANTHROPIC_API_KEY": "k", "HTTPS_PROXY": "http://proxy:3128",
            "SSL_CERT_FILE": "/etc/ssl/ca.pem", "PATH": "/usr/bin"})
        self.assertEqual(env["HOME"], "/home/sisagent")
        self.assertEqual(env["USER"], "sisagent")
        self.assertEqual(env["LOGNAME"], "sisagent")
        # The evaluator's locations are unusable and not passed on; one
        # inside the agent's home is kept.
        self.assertNotIn("TMPDIR", env)
        self.assertNotIn("CLAUDE_CONFIG_DIR", env)
        self.assertEqual(env["CODEX_HOME"], "/home/sisagent/.codex")
        for name in ("ANTHROPIC_API_KEY", "HTTPS_PROXY", "SSL_CERT_FILE",
                     "PATH"):
            self.assertIn(name, env)

    def test_a_sudo_refusal_names_the_sudoers_rule(self):
        runner = Recorder({"probe": FakeProc(
            b"", 1, b"sudo: a password is required\n")})
        agent = principal(runner=runner)
        with self.assertRaisesRegex(AgentPrincipalError,
                                    r"NOPASSWD: /usr/bin/python3"):
            agent.probe(["/x"])


def _probe(paths=None, executables=None, *, uid=None, owned=True):
    return {"uid": unprivileged_uid() if uid is None else uid, "gid": 1,
            "groups": [1],
            "paths": paths or {}, "executables": executables or {},
            "credentials": {},
            "home": {"path": "/home/sisagent", "owned": owned,
                     "writable": owned}}


@unittest.skipUnless(POSIX, "agent principals are POSIX-only")
class PreflightTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.private = Path(temp.name) / "private"
        (self.private / "hidden").mkdir(parents=True)
        (self.private / "hidden" / "test_x.py").write_text("x")
        (self.private / "trust.json").write_text("{}")

    def run_preflight(self, answer):
        runner = Recorder({"probe": answer})
        agent = principal(runner=runner)
        return agent, runner

    def test_the_sample_covers_the_roots_and_their_files(self):
        sample = sample_paths([self.private, self.private / "missing"])
        self.assertIn(str(self.private), sample)
        self.assertIn(str(self.private / "trust.json"), sample)
        self.assertIn(str(self.private / "hidden" / "test_x.py"), sample)
        self.assertNotIn(str(self.private / "missing"), sample)

    def test_preflight_passes_when_nothing_is_readable(self):
        def answer():
            return _probe(
                {path: {"exists": None, "readable": False,
                        "searchable": False}
                 for path in sample_paths([self.private])},
                {"/opt/claude": True})
        agent, runner = self.run_preflight(answer)
        record = agent.preflight([self.private], executables=["/opt/claude"])
        self.assertEqual(record["readable_paths"], 0)
        self.assertGreaterEqual(record["checked_paths"], 3)
        request = json.loads(runner.calls[0]["proc"].stdin.getvalue())
        self.assertIn(str(self.private / "trust.json"), request["paths"])

    def test_a_readable_private_path_aborts(self):
        target = str(self.private / "trust.json")
        agent, _ = self.run_preflight(_probe(
            {target: {"exists": True, "readable": True,
                      "searchable": False}}))
        with self.assertRaisesRegex(AgentPrincipalError,
                                    "can read evaluator material: .*trust"):
            agent.preflight([self.private])

    def test_a_searchable_private_directory_aborts(self):
        agent, _ = self.run_preflight(_probe(
            {str(self.private): {"exists": True, "readable": False,
                                 "searchable": True}}))
        with self.assertRaisesRegex(AgentPrincipalError, "evaluator material"):
            agent.preflight([self.private])

    def test_an_unexecutable_cli_a_foreign_home_or_wrong_uid_abort(self):
        for answer, pattern in (
                (_probe(executables={"/home/sispilot/claude": False}),
                 "cannot execute /home/sispilot/claude"),
                (_probe(owned=False), "does not own a writable home"),
                (_probe(uid=0), "helper ran as uid 0")):
            agent, _ = self.run_preflight(answer)
            with self.assertRaisesRegex(AgentPrincipalError, pattern):
                agent.preflight([self.private],
                                executables=["/home/sispilot/claude"])

    def test_no_private_path_is_not_a_pass(self):
        agent, _ = self.run_preflight(_probe())
        with self.assertRaisesRegex(AgentPrincipalError, "no private path"):
            agent.preflight([self.private / "missing"])


def _tar(entries) -> io.BytesIO:
    """A tar stream from ``(name, type, data_or_link, mode)`` tuples."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, kind, data, mode in entries:
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.type = kind
            payload = None
            if kind == tarfile.REGTYPE:
                member.size = len(data)
                payload = io.BytesIO(data)
            elif kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = data
            archive.addfile(member, payload)
    buffer.seek(0)
    return buffer


ROOT_DIR = (".", tarfile.DIRTYPE, None, 0o755)


@unittest.skipUnless(POSIX, "agent principals are POSIX-only")
class ReceiveTreeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.dest = self.root / "dest"
        self.dest.mkdir()

    def receive(self, entries, **kwargs):
        receive_tree(_tar(entries), self.dest, **kwargs)

    def test_files_dirs_links_and_modes_come_back(self):
        self.receive([
            ROOT_DIR,
            ("./src", tarfile.DIRTYPE, None, 0o555),
            ("./src/a.py", tarfile.REGTYPE, b"A = 1\n", 0o644),
            ("./run.sh", tarfile.REGTYPE, b"#!/bin/sh\n", 0o4755),
            ("./copy.py", tarfile.LNKTYPE, "src/a.py", 0o644),
            ("./link", tarfile.SYMTYPE, "/etc/passwd", 0o777),
        ])
        self.assertEqual((self.dest / "src" / "a.py").read_text(), "A = 1\n")
        self.assertEqual((self.dest / "copy.py").read_text(), "A = 1\n")
        self.assertNotEqual((self.dest / "copy.py").stat().st_ino,
                            (self.dest / "src" / "a.py").stat().st_ino)
        # Set-id bits are dropped; a read-only directory is applied last.
        self.assertEqual(stat.S_IMODE((self.dest / "run.sh").stat().st_mode),
                         0o755)
        self.assertEqual(stat.S_IMODE((self.dest / "src").stat().st_mode),
                         0o555)
        # A symlink stays a link (the evaluator refuses links later).
        self.assertTrue((self.dest / "link").is_symlink())
        os.chmod(self.dest / "src", 0o755)

    def test_unsafe_names_and_types_are_refused(self):
        cases = [
            [ROOT_DIR, ("../escape", tarfile.REGTYPE, b"x", 0o644)],
            [ROOT_DIR, ("/abs", tarfile.REGTYPE, b"x", 0o644)],
            [ROOT_DIR, ("./fifo", tarfile.FIFOTYPE, None, 0o644)],
            [ROOT_DIR, ("./dev", tarfile.CHRTYPE, None, 0o644)],
            # A file below a symlinked "directory" is never written
            # through the link.
            [ROOT_DIR, ("./d", tarfile.SYMTYPE, str(self.root), 0o777),
             ("./d/planted", tarfile.REGTYPE, b"x", 0o644)],
            [ROOT_DIR, ("./x/y", tarfile.REGTYPE, b"x", 0o644)],
            [ROOT_DIR, ("./h", tarfile.LNKTYPE, "/etc/passwd", 0o644)],
            [ROOT_DIR, ("./a", tarfile.REGTYPE, b"x", 0o644),
             ("./a", tarfile.REGTYPE, b"y", 0o644)],
            [("./a", tarfile.REGTYPE, b"x", 0o644)],
        ]
        for entries in cases:
            shutil.rmtree(self.dest)
            self.dest.mkdir()
            with self.subTest(entries=entries[-1][0]):
                with self.assertRaises(AgentPrincipalError):
                    self.receive(entries)
        self.assertFalse((self.root / "planted").exists())

    def test_size_and_count_are_bounded(self):
        with self.assertRaisesRegex(AgentPrincipalError, "too large"):
            self.receive([ROOT_DIR, ("./a", tarfile.REGTYPE, b"x" * 10,
                                     0o644)], max_bytes=5)
        shutil.rmtree(self.dest)
        self.dest.mkdir()
        with self.assertRaisesRegex(AgentPrincipalError, "too many"):
            self.receive([ROOT_DIR] + [
                (f"./f{i}", tarfile.REGTYPE, b"", 0o644) for i in range(5)],
                max_entries=3)


@unittest.skipUnless(POSIX, "agent principals are POSIX-only")
class CheckoutTests(unittest.TestCase):
    """The real helper program, run as the current user without sudo."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.home = self.root / "agent-home"
        self.home.mkdir(mode=0o700)
        (self.home / ".claude").mkdir()
        (self.home / ".claude" / ".credentials.json").write_text("{}")
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)
        self.workspace = self.work / "arm-A-1"
        self.workspace.mkdir()
        (self.workspace / "pkg").mkdir()
        (self.workspace / "pkg" / "mod.py").write_text("X = 1\n")
        script = self.workspace / "run.sh"
        script.write_text("#!/bin/sh\n")
        script.chmod(0o750)
        self.runner = local_runner()
        self.agent = principal(home=str(self.home), runner=self.runner)

    def test_a_round_trip_without_edits_keeps_the_tree_digest(self):
        before = tree_digest(self.workspace)
        with self.agent.checkout(self.workspace) as path:
            self.assertTrue(path.startswith(str(self.home / "sis-work")))
            self.assertNotEqual(Path(path), self.workspace)
            self.assertEqual((Path(path) / "pkg" / "mod.py").read_text(),
                             "X = 1\n")
            turn_home = self.agent.environment({})["HOME"]
            self.assertTrue(Path(turn_home, ".claude",
                                 ".credentials.json").is_file())
        self.assertEqual(tree_digest(self.workspace), before)
        # Nothing of the turn is left in the agent's work area, and the
        # agent processes were killed before and after the turn.
        self.assertEqual(list((self.home / "sis-work").iterdir()), [])
        self.assertEqual(self.agent.environment({})["HOME"], str(self.home))
        self.assertGreaterEqual(len(self.runner.kills), 2)
        self.assertEqual(list(self.work.iterdir()), [self.workspace])

    def test_edits_come_back_even_from_unreadable_agent_files(self):
        with self.agent.checkout(self.workspace) as path:
            agent_path = Path(path)
            (agent_path / "pkg" / "mod.py").write_text("X = 2\n")
            (agent_path / "new.py").write_text("NEW = 1\n")
            (agent_path / "new.py").chmod(0o000)
            locked = agent_path / "locked"
            locked.mkdir()
            (locked / "inside.txt").write_text("in")
            locked.chmod(0o000)
            (agent_path / "run.sh").unlink()
        self.assertEqual((self.workspace / "pkg" / "mod.py").read_text(),
                         "X = 2\n")
        new = self.workspace / "new.py"
        self.assertEqual(stat.S_IMODE(new.stat().st_mode), 0o000)
        new.chmod(0o600)
        self.assertEqual(new.read_text(), "NEW = 1\n")
        locked = self.workspace / "locked"
        self.assertEqual(stat.S_IMODE(locked.stat().st_mode), 0o000)
        locked.chmod(0o700)
        self.assertEqual((locked / "inside.txt").read_text(), "in")
        self.assertFalse((self.workspace / "run.sh").exists())
        self.assertEqual(list((self.home / "sis-work").iterdir()), [])

    def test_a_failed_copy_back_leaves_the_workspace_unchanged(self):
        before = tree_digest(self.workspace)

        def broken_pack(argv, **kwargs):
            if argv[-1] == "pack":
                return FakeProc(b"not a tar stream", 0)
            return self.runner(argv, **kwargs)
        self.agent._runner = broken_pack
        with self.assertRaisesRegex(AgentPrincipalError, "archive"):
            with self.agent.checkout(self.workspace) as path:
                (Path(path) / "pkg" / "mod.py").write_text("X = 3\n")
        self.assertEqual(tree_digest(self.workspace), before)
        # The body's own failure wins over a failed copy-back.
        with self.assertRaisesRegex(ValueError, "agent failed"):
            with self.agent.checkout(self.workspace):
                raise ValueError("agent failed")
        self.assertEqual(list(self.work.iterdir()), [self.workspace])

    @unittest.skipIf(os.geteuid() == 0, "root reads a mode-000 file")
    def test_an_unreadable_workspace_file_fails_the_copy_in(self):
        # The archive would end cleanly before the file it could not
        # read, and the helper would unpack a partial tree.
        locked = self.workspace / "pkg" / "secret.py"
        locked.write_text("S = 1\n")
        locked.chmod(0o000)
        with self.assertRaisesRegex(AgentPrincipalError,
                                    "workspace copy incomplete"):
            with self.agent.checkout(self.workspace):
                self.fail("the agent must not work on a partial tree")
        self.assertEqual(stat.S_IMODE(locked.stat().st_mode), 0o000)

    def test_a_file_vanishing_mid_walk_fails_the_copy_in(self):
        before = tree_digest(self.workspace)
        original = tarfile.TarFile.add

        def vanishing(archive, name, arcname=None, recursive=True, *,
                      filter=None):
            if arcname == "./pkg":
                raise FileNotFoundError(2, "vanished", name)
            return original(archive, name, arcname, recursive, filter=filter)

        with mock.patch.object(tarfile.TarFile, "add", vanishing):
            with self.assertRaisesRegex(AgentPrincipalError,
                                        "workspace copy incomplete"):
                with self.agent.checkout(self.workspace):
                    self.fail("the agent must not work on a partial tree")
        self.assertEqual(tree_digest(self.workspace), before)

    def test_one_turn_at_a_time(self):
        with self.agent.checkout(self.workspace):
            with self.assertRaisesRegex(AgentPrincipalError, "one turn"):
                with self.agent.checkout(self.workspace):
                    pass


class FakePrincipal:
    """Launches directly as the current user; records kills."""

    uid = 4242

    def __init__(self, root: Path, user: str = "sisagent",
                 preflight_error: str | None = None) -> None:
        self.root = root
        self.user = user
        self.preflight_error = preflight_error
        self.checked: list[str] = []
        self.kills = 0
        self.launched: list[dict] = []
        self.checkouts = 0
        self.procs: list[subprocess.Popen] = []

    def launch(self, argv, *, cwd, env):
        self.launched.append({"argv": list(argv), "cwd": cwd,
                              "env": dict(env)})
        proc = subprocess.Popen(argv, cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                start_new_session=True)
        self.procs.append(proc)
        return proc

    def kill_all(self):
        self.kills += 1
        for proc in self.procs:
            ClaudeCodeAdapter._kill_group(proc)
        return {"ok": True}

    def environment(self, env):
        result = dict(env)
        result.update({"HOME": str(self.root / "agent-home"),
                       "USER": self.user, "LOGNAME": self.user})
        return result

    @contextmanager
    def checkout(self, workspace):
        self.checkouts += 1
        copy = self.root / f"agent-copy-{self.checkouts}"
        shutil.copytree(workspace, copy)
        try:
            yield str(copy)
        finally:
            self.kill_all()
            shutil.rmtree(workspace)
            shutil.copytree(copy, workspace)
            shutil.rmtree(copy)

    def credentials(self):
        return {".claude/.credentials.json": False}

    def identity(self):
        return {"user": self.user, "uid": self.uid,
                "mechanism": "sudo_helper_v1"}

    def describe(self):
        return {"separated": True, "user": self.user, "uid": self.uid}

    def preflight(self, private_paths, *, executables=()):
        self.checked = [str(path) for path in private_paths]
        if self.preflight_error:
            raise AgentPrincipalError(self.preflight_error)
        return {"checked_paths": len(self.checked), "readable_paths": 0}


@unittest.skipUnless(POSIX, "the fake CLI is a POSIX executable script")
class AdapterPrincipalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.principal = FakePrincipal(self.root)

    def test_the_cli_is_launched_through_the_principal(self):
        binary = write_fake_claude(self.root, standard_stream())
        adapter = ClaudeCodeAdapter(claude_path=binary, wall_seconds=30,
                                    principal=self.principal)
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-x",
                                          "HOME": "/home/evaluator"}):
            events = list(adapter.start_task("fix", str(self.workspace)))
        self.assertEqual(len(self.principal.launched), 1)
        launched = self.principal.launched[0]
        self.assertEqual(launched["env"]["HOME"],
                         str(self.root / "agent-home"))
        self.assertEqual(launched["env"]["ANTHROPIC_API_KEY"], "sk-x")
        self.assertEqual(launched["cwd"], str(self.workspace))
        self.assertEqual(events[-1].payload["summary"]["cli_exit_status"], 0)
        # Turn cleanup kills as the agent user.
        self.assertGreaterEqual(self.principal.kills, 1)

    def test_the_watchdog_kills_as_the_agent_user(self):
        binary = write_fake_claude(self.root, standard_stream(),
                                   sleep_after=60)
        adapter = ClaudeCodeAdapter(claude_path=binary, wall_seconds=1,
                                    principal=self.principal)
        start = time.monotonic()
        events = list(adapter.start_task("fix", str(self.workspace)))
        self.assertLess(time.monotonic() - start, 30)
        summary = events[-1].payload["summary"]
        self.assertTrue(summary["timed_out"])
        self.assertGreaterEqual(self.principal.kills, 1)

    def test_codex_adapter_uses_the_principal_too(self):
        fake = self.root / "codex"
        fake.write_text(textwrap.dedent(f"""\
            #!{sys.executable}
            import json, sys
            print(json.dumps({{"type": "turn.completed",
                              "usage": {{"input_tokens": 1}}}}))
            """))
        fake.chmod(0o755)
        adapter = CodexCliAdapter(codex_path=fake, wall_seconds=30,
                                  principal=self.principal)
        events = list(adapter.start_task("fix", str(self.workspace),
                                         sandbox="workspace_write"))
        self.assertEqual(len(self.principal.launched), 1)
        self.assertEqual(self.principal.launched[0]["env"]["USER"],
                         "sisagent")
        self.assertEqual(events[-1].payload["summary"]["cli_exit_status"], 0)
        self.assertGreaterEqual(self.principal.kills, 1)

    def test_a_relative_workspace_is_refused_under_a_principal(self):
        binary = write_fake_claude(self.root, standard_stream())
        adapter = ClaudeCodeAdapter(claude_path=binary,
                                    principal=self.principal)
        with self.assertRaises(ValueError):
            adapter.start_task("fix", "relative/ws")


@unittest.skipUnless(POSIX, "the fake CLI is a POSIX executable script")
class AgentPrincipalUseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        (self.workspace / "base.py").write_text("B = 1\n")
        self.principal = FakePrincipal(self.root)

    def agent(self, **kwargs):
        binary = write_fake_claude(self.root, standard_stream(), **kwargs)
        adapter = ClaudeCodeAdapter(claude_path=binary, wall_seconds=30,
                                    principal=self.principal)
        return ClaudeCodeAgent(adapter=adapter, prompts={"t1": "fix"},
                               principal=self.principal)

    def test_the_agent_edits_its_copy_and_the_edit_comes_back(self):
        agent = self.agent()
        usage = agent(_ctx(self.workspace))
        self.assertEqual(usage["tools_used"], 2)
        self.assertEqual(self.principal.checkouts, 1)
        self.assertNotEqual(self.principal.launched[0]["cwd"],
                            str(self.workspace))
        self.assertEqual((self.workspace / "solution.py").read_text(),
                         "OK = 1\n")

    def test_no_action_is_judged_on_the_returned_tree(self):
        agent = self.agent(edit=False)
        with self.assertRaisesRegex(RuntimeError, "real_agent_no_action"):
            agent(_ctx(self.workspace))

    def test_a_principal_failure_is_an_ordinary_metered_failure(self):
        agent = self.agent()

        @contextmanager
        def failing(workspace):
            raise AgentPrincipalError("sudo refused")
            yield  # pragma: no cover

        self.principal.checkout = failing
        meter = UsageMeter()
        with self.assertRaisesRegex(RuntimeError,
                                    "real_agent_principal_failed"):
            agent(_ctx(self.workspace, meter))
        self.assertTrue(meter.tokens_verified)
        self.assertEqual(meter.tokens, 0)

    def test_codex_agent_checks_out_through_the_principal(self):
        class Adapter:
            def __init__(self):
                self.workspaces = []

            def start_task(self, prompt, workspace, **kwargs):
                self.workspaces.append(workspace)
                (Path(workspace) / "out.txt").write_text("ok")
                yield SimpleNamespace(event_type="edit", payload={
                    "sdk_method": "item.completed",
                    "summary": {"item_type": "file_change"}})
                yield SimpleNamespace(event_type="completion", payload={
                    "sdk_method": "turn.completed",
                    "summary": {"token_usage": {"input_tokens": 3,
                                                "output_tokens": 4}}})
                yield SimpleNamespace(event_type="completion", payload={
                    "sdk_method": "sis/process_exit",
                    "summary": {"cli_exit_status": 0}})

            def close(self):
                pass

        adapter = Adapter()
        agent = CodexCliAgent(adapter=adapter, prompts={"t1": "fix"},
                              principal=self.principal)
        usage = agent(_ctx(self.workspace))
        self.assertEqual(usage["tools_used"], 1)
        self.assertNotEqual(adapter.workspaces[0], str(self.workspace))
        self.assertEqual((self.workspace / "out.txt").read_text(), "ok")

    def test_status_reads_credentials_from_the_agent_home(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("shutil.which", return_value="/opt/claude"):
            status = claude_code_agent_status(self.principal)
        self.assertEqual(status["agent_user"], "sisagent")
        self.assertFalse(status["authenticated"])
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k"},
                             clear=True), \
                mock.patch("shutil.which", return_value="/opt/claude"):
            status = claude_code_agent_status(self.principal)
        self.assertTrue(status["authenticated"])



def _integration_user() -> tuple[str | None, str]:
    user = os.environ.get("SIS_TEST_AGENT_USER")
    if not POSIX:
        return None, "agent principals are POSIX-only"
    if not user:
        return None, ("set SIS_TEST_AGENT_USER to a dedicated second user"
                      " that 'sudo -n -u USER /usr/bin/python3' can become")
    try:
        pwd.getpwnam(user)
    except KeyError:
        return None, f"SIS_TEST_AGENT_USER={user} does not exist"
    sudo = shutil.which("sudo")
    if sudo is None or not Path(DEFAULT_PYTHON).exists():
        return None, "sudo or /usr/bin/python3 is missing"
    probe = subprocess.run(
        [sudo, "-n", "-u", user, "--", DEFAULT_PYTHON, "-I", "-S", "-c",
         "pass"], capture_output=True, cwd="/", start_new_session=True)
    if probe.returncode != 0:
        return None, (f"sudo -n -u {user} {DEFAULT_PYTHON} is not allowed: "
                      + probe.stderr.decode(errors="replace").strip())
    return user, ""


AGENT_USER, SKIP_REASON = _integration_user()

FAKE_AGENT = r'''#!/usr/bin/python3
import json, os, subprocess, sys, time
if sys.argv[1:] == ["--version"]:
    print("2.1.328 (Claude Code)")
    raise SystemExit(0)
report = {"uid": os.getuid(), "home": os.environ.get("HOME"),
          "home_owner": os.stat(os.environ["HOME"]).st_uid,
          "api_key": os.environ.get("ANTHROPIC_API_KEY"),
          "cwd": os.getcwd(), "private": {}}
for path in json.loads(os.environ.get("SIS_FAKE_PRIVATE", "[]")):
    try:
        with open(path, "rb") as handle:
            handle.read(1)
        report["private"][path] = "read"
    except OSError as exc:
        report["private"][path] = type(exc).__name__
with open("solution.py", "w") as handle:
    handle.write("OK = 1\n")
with open("agent_report.json", "w") as handle:
    json.dump(report, handle)
if os.environ.get("SIS_FAKE_HANG"):
    # A child that leaves the process group, then hang.
    subprocess.Popen(["sleep", "300"], start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(300)
for line in STREAM:
    print(json.dumps(line), flush=True)
'''


def _agent_processes(uid: int) -> list[int]:
    found = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            text = Path("/proc", name, "status").read_text()
        except OSError:
            continue
        fields = dict(line.split(":", 1) for line in text.splitlines()
                      if ":" in line)
        if int(fields["Uid"].split()[0]) == uid and \
                fields["State"].strip()[:1] not in "ZX":
            found.append(int(name))
    return found


@unittest.skipUnless(AGENT_USER, SKIP_REASON)
class AgentPrincipalIntegrationTests(unittest.TestCase):
    """A real second user: the fake CLI runs as it, through sudo."""

    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="sis-principal-"))
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.private = self.temp / "private"
        self.private.mkdir(mode=0o700)
        (self.private / "test_hidden.py").write_text("SECRET = 1\n")
        self.public = self.temp / "public"
        self.public.mkdir()
        os.chmod(self.temp, 0o711)
        os.chmod(self.public, 0o755)
        fake = self.public / "claude"
        fake.write_text(FAKE_AGENT.replace("STREAM", "json.loads(%r)" % (
            json.dumps(standard_stream()),)))
        fake.chmod(0o755)
        self.fake = fake
        self.work = self.temp / "work"
        self.work.mkdir(mode=0o700)
        self.workspace = self.work / "arm-A-x"
        self.workspace.mkdir()
        (self.workspace / "base.py").write_text("B = 1\n")
        self.principal = AgentPrincipal.resolve(AGENT_USER)
        self.addCleanup(self.principal.kill_all)

    def agent(self, wall_seconds=60):
        adapter = ClaudeCodeAdapter(claude_path=self.fake,
                                    wall_seconds=wall_seconds,
                                    principal=self.principal)
        return ClaudeCodeAgent(adapter=adapter, prompts={"t1": "fix"},
                               principal=self.principal)

    def test_the_agent_edits_its_workspace_but_not_the_private_files(self):
        self.principal.preflight([self.private],
                                 executables=[str(self.fake)])
        planted = str(self.private / "test_hidden.py")
        agent = self.agent()
        # Not an allowlisted variable: the adapter's env_extra passes it.
        agent._adapter._env_extra["SIS_FAKE_PRIVATE"] = json.dumps([planted])
        with mock.patch.dict(os.environ,
                             {"ANTHROPIC_API_KEY": "sk-integration"}):
            usage = agent(_ctx(self.workspace))
        self.assertEqual(usage["tools_used"], 2)
        self.assertEqual((self.workspace / "solution.py").read_text(),
                         "OK = 1\n")
        report = json.loads((self.workspace / "agent_report.json")
                            .read_text())
        uid = pwd.getpwnam(AGENT_USER).pw_uid
        self.assertEqual(report["uid"], uid)
        self.assertEqual(report["home_owner"], uid)
        self.assertEqual(report["api_key"], "sk-integration")
        self.assertEqual(report["private"][planted], "PermissionError")
        # The returned tree is the evaluator's own.
        for path in self.workspace.rglob("*"):
            self.assertEqual(path.lstat().st_uid, os.geteuid())
        self.assertEqual(_agent_processes(uid), [])

    def test_the_timeout_kills_every_agent_process(self):
        uid = pwd.getpwnam(AGENT_USER).pw_uid
        agent = self.agent(wall_seconds=3)
        agent._adapter._env_extra["SIS_FAKE_HANG"] = "1"
        start = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "real_agent_timeout"):
            agent(_ctx(self.workspace))
        self.assertLess(time.monotonic() - start, 60)
        self.assertEqual(_agent_processes(uid), [])
        # The partial work still came back to the evaluator's tree.
        self.assertTrue((self.workspace / "solution.py").is_file())

    def test_preflight_aborts_when_the_private_dir_is_readable(self):
        os.chmod(self.private, 0o755)
        os.chmod(self.private / "test_hidden.py", 0o644)
        with self.assertRaisesRegex(AgentPrincipalError,
                                    "can read evaluator material"):
            self.principal.preflight([self.private],
                                     executables=[str(self.fake)])


if __name__ == "__main__":
    unittest.main()
