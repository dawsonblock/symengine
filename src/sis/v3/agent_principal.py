"""Run the coding agent under test as a separate, unprivileged OS user.

Without a principal, the campaign process launches the agent CLI as its
own user, so the agent could read everything the evaluator holds: hidden
tests, the verifier registry and keys, ``trust.json`` and the state
directory. :class:`AgentPrincipal` launches the CLI as a dedicated user
instead, through ``sudo -n -u USER`` and a small helper program that SIS
passes to the system Python on the command line. Nothing secret is on
any command line: the helper reads its request (the agent's argv,
working directory and allowlisted environment, credentials included) as
one JSON line from a pipe.

Mechanism
    The evaluator stays non-root. ``sudo`` is the only privileged step, and
    it only ever becomes the agent user, which has no privileges of its
    own. One sudoers rule is needed::

        EVALUATOR ALL=(AGENT) NOPASSWD: /usr/bin/python3

    No ``SETENV`` and no ``env_keep``: the helper replaces the environment
    sudo built with exactly the one SIS sends.

Workspace
    The agent never touches an evaluator-owned tree. Before a turn the
    evaluator streams the task workspace as a tar archive to the helper,
    which unpacks it into a fresh directory the agent user owns under
    ``<agent home>/sis-work``, next to a fresh per-turn ``HOME``. After the
    turn every process of the agent user is killed (``kill(-1, SIGKILL)``
    as that user, repeated until ``/proc`` shows none alive), the helper
    streams the tree back, and the evaluator unpacks it into a new
    directory beside the original with its own ownership, validating
    every entry (regular files, directories and symlinks stored as links;
    no device, FIFO, absolute or ``..`` name; bounded size and count;
    set-id and sticky bits dropped), then swaps it in. The tree that is
    digested and graded is therefore evaluator-owned, inside the
    evaluator's private work root, and no agent process exists any more,
    so :func:`sis.v3.runner.tree_digest` and the verifier's
    ``submission_changed_during_evaluation`` check keep their guarantee.

Process control
    A non-root parent cannot signal another user's processes: ``killpg`` of
    the sudo process group kills ``sudo`` and leaves the agent running.
    :meth:`AgentPrincipal.kill_all` therefore runs the kill as the agent
    user, which reaches everything it started, including processes that
    left the process group. That is why the agent user must be dedicated to
    SIS and why one principal serves one turn at a time.

Fail closed
    :meth:`AgentPrincipal.preflight` runs before any agent turn. It checks,
    as the agent user, that a sample of the private paths is neither
    readable nor (for directories) searchable, that the agent CLI is
    executable, and that the agent's home is its own, and raises
    :class:`AgentPrincipalError` naming what is wrong.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

#: Recorded in provenance; bump when the launch or transfer protocol changes.
MECHANISM = "sudo_helper_v1"
DEFAULT_PYTHON = "/usr/bin/python3"
_USER_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_WORK_DIR = "sis-work"
_HELPER_TIMEOUT = 120
_MAX_HELPER_OUTPUT = 1 << 20
_MAX_PROBE_PATHS = 512
#: Bounds on a tree returned by the agent.
MAX_RETURN_BYTES = 8 << 30
MAX_RETURN_ENTRIES = 200_000
#: Credential files copied from the agent's own home into each per-turn
#: home (relative to the home; copied only if present).
CREDENTIAL_FILES = (".claude/.credentials.json", ".codex/auth.json")
#: Environment variables that name a location; kept only when it is inside
#: the agent's own home, since the agent cannot use the evaluator's.
_LOCATION_VARIABLES = ("TMPDIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME")
#: The environment sudo itself runs with (it builds the target's anyway).
_SUDO_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class AgentPrincipalError(RuntimeError):
    """The agent principal is unusable or would expose evaluator material."""


# The helper runs as the agent user with ``python3 -I -S -c``: no site
# packages, no environment-controlled imports, no file the agent user would
# need to read. Its first stdin line is the JSON request; ``unpack`` reads a
# tar stream after it. It never imports anything outside the stdlib.
HELPER_SOURCE = r'''
import json, os, shutil, signal, stat, sys, tarfile, time

def out(document):
    sys.stdout.write(json.dumps(document) + "\n")
    sys.stdout.flush()

def own_dir(path, create):
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise SystemExit("not an owned directory: " + path)

def child(base, name):
    if not name or "/" in name or name in (".", ".."):
        raise SystemExit("bad name")
    return os.path.join(base, name)

def make_accessible(top):
    # The agent may have left its own directories unreadable; it owns them
    # all. Returns the modes changed, so a pack can record the originals.
    changed = {}
    for path in [top]:
        info = os.lstat(path)
        if stat.S_ISDIR(info.st_mode) and info.st_mode & 0o700 != 0o700:
            changed[path] = stat.S_IMODE(info.st_mode)
            os.chmod(path, changed[path] | 0o700)
    for root, dirs, files in os.walk(top):
        for name in dirs:
            path = os.path.join(root, name)
            info = os.lstat(path)
            if stat.S_ISDIR(info.st_mode) and info.st_mode & 0o700 != 0o700:
                changed[path] = stat.S_IMODE(info.st_mode)
                os.chmod(path, changed[path] | 0o700)
    return changed

def alive():
    me, found = os.getpid(), []
    try:
        names = os.listdir("/proc")
    except OSError:
        return found
    for name in names:
        if not name.isdigit() or int(name) == me:
            continue
        try:
            with open("/proc/%s/status" % name) as handle:
                text = handle.read()
        except OSError:
            continue
        fields = dict(line.split(":", 1) for line in text.splitlines()
                      if ":" in line)
        uid = fields.get("Uid", "").split()
        state = fields.get("State", "").strip()[:1]
        if uid and int(uid[0]) == os.getuid() and state not in ("Z", "X"):
            found.append(int(name))
    return found

def op_exec(request):
    os.chdir(request["cwd"])
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    try:
        os.execve(request["argv"][0], request["argv"], request["env"])
    except OSError as exc:
        sys.stderr.write("sis-agent-helper: exec failed: %s\n" % exc)
        os._exit(127)

def op_kill(request):
    for rounds in range(1, 401):
        try:
            os.kill(-1, signal.SIGKILL)
        except ProcessLookupError:
            pass
        remaining = alive()
        if not remaining:
            out({"ok": True, "rounds": rounds})
            return
        time.sleep(0.025)
    out({"ok": False, "remaining": remaining[:32]})
    raise SystemExit(3)

def readable(path):
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return {"exists": False, "readable": False, "searchable": False}
    except OSError:
        return {"exists": None, "readable": False, "searchable": False}
    result = {"exists": True, "readable": os.access(path, os.R_OK),
              "searchable": False}
    try:
        if stat.S_ISDIR(info.st_mode):
            result["searchable"] = os.access(path, os.X_OK)
            os.listdir(path)
        else:
            with open(path, "rb") as handle:
                handle.read(1)
        result["readable"] = True
    except OSError:
        pass
    return result

def op_probe(request):
    home = request.get("home") or ""
    home_state = {"path": home, "owned": False, "writable": False}
    try:
        info = os.lstat(home)
        home_state["owned"] = (stat.S_ISDIR(info.st_mode)
                               and info.st_uid == os.getuid())
        home_state["writable"] = os.access(home, os.W_OK | os.X_OK)
    except OSError:
        pass
    out({"uid": os.getuid(), "gid": os.getgid(),
         "groups": sorted(os.getgroups()),
         "paths": {path: readable(path) for path in request["paths"]},
         "executables": {path: os.access(path, os.X_OK)
                         for path in request["executables"]},
         "credentials": {name: os.path.isfile(os.path.join(home, name))
                         for name in request.get("credentials", ())},
         "home": home_state})

def op_unpack(request):
    base = request["base"]
    own_dir(os.path.dirname(base), False)
    own_dir(base, True)
    workspace = child(base, request["workspace"])
    home = child(base, request["home"])
    os.mkdir(home, 0o700)
    for name in request.get("credentials", ()):
        source = os.path.join(request["persistent_home"], name)
        if os.path.isfile(source) and not os.path.islink(source):
            target = os.path.join(home, name)
            os.makedirs(os.path.dirname(target), 0o700, exist_ok=True)
            shutil.copyfile(source, target)
            os.chmod(target, 0o600)
    os.mkdir(workspace, 0o700)
    archive = tarfile.open(fileobj=sys.stdin.buffer, mode="r|")
    options = {}
    if hasattr(tarfile, "fully_trusted_filter"):
        options["filter"] = "fully_trusted"
    archive.extractall(workspace, **options)
    archive.close()
    out({"workspace": workspace, "home": home})

def op_pack(request):
    top = child(request["base"], request["workspace"])
    original = make_accessible(top)
    archive = tarfile.open(fileobj=sys.stdout.buffer, mode="w|",
                           format=tarfile.PAX_FORMAT)
    for root, dirs, files in os.walk(top):
        dirs.sort()
        for name in [""] + sorted(dirs) + sorted(files):
            path = os.path.join(root, name) if name else root
            if not name and root != top:
                continue
            info = os.lstat(path)
            relative = os.path.relpath(path, top)
            if stat.S_ISREG(info.st_mode) and not info.st_mode & 0o400:
                os.chmod(path, stat.S_IMODE(info.st_mode) | 0o400)
            member = archive.gettarinfo(path, relative)
            if member is None:
                continue
            member.mode = original.get(path, stat.S_IMODE(info.st_mode))
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            if member.isreg():
                with open(path, "rb") as handle:
                    archive.addfile(member, handle)
            else:
                archive.addfile(member)
    archive.close()
    sys.stdout.buffer.flush()

def op_remove(request):
    for name in request["names"]:
        path = child(request["base"], name)
        if not os.path.lexists(path):
            continue
        if os.path.isdir(path) and not os.path.islink(path):
            make_accessible(path)
            os.chmod(path, 0o700)
            shutil.rmtree(path)
        else:
            os.unlink(path)
    out({"ok": True})

def main():
    request = json.loads(sys.stdin.buffer.readline(1 << 22))
    {"exec": op_exec, "kill": op_kill, "probe": op_probe,
     "unpack": op_unpack, "pack": op_pack,
     "remove": op_remove}[sys.argv[1]](request)

main()
'''


def _inside(path: str, root: str) -> bool:
    try:
        PurePosixPath(path).relative_to(PurePosixPath(root))
    except ValueError:
        return False
    return True


class AgentPrincipal:
    """A dedicated OS user the agent CLI runs as (see the module docstring).

    ``runner`` replaces :func:`subprocess.Popen` for the helper calls in
    tests; it receives the same arguments.
    """

    def __init__(self, user: str, *, uid: int, gid: int, home: str,
                 shell: str = "/bin/sh", sudo: str = "/usr/bin/sudo",
                 python: str = DEFAULT_PYTHON, runner=None) -> None:
        if not isinstance(user, str) or not _USER_NAME.fullmatch(user):
            raise AgentPrincipalError(
                f"agent user {user!r} is not a plain user name")
        if type(uid) is not int or uid <= 0:
            raise AgentPrincipalError(
                f"agent user {user} must not be root (uid {uid})")
        if hasattr(os, "geteuid") and uid == os.geteuid():
            raise AgentPrincipalError(
                f"agent user {user} is the evaluator's own user")
        if not os.path.isabs(home):
            raise AgentPrincipalError(f"agent user {user} has no home")
        self.user = user
        self.uid = uid
        self.gid = gid
        self.home = home
        # A service account's nologin shell would break the agent's shell
        # tool; sudo itself never consults it.
        self.shell = (shell if shell and os.path.basename(shell) not in
                      ("nologin", "false") else "/bin/sh")
        self.sudo = sudo
        self.python = python
        self.work_base = os.path.join(home, _WORK_DIR)
        self._runner = runner or subprocess.Popen
        self._lock = threading.Lock()
        # Held by kills and by every workspace transfer: a kill (an abort
        # from another thread) never lands in the middle of a copy.
        self._kill_lock = threading.RLock()
        self._turn_home: str | None = None

    @classmethod
    def resolve(cls, user: str, *, python: str | None = None,
                runner=None) -> "AgentPrincipal":
        """Look ``user`` up in the password database and find ``sudo``."""
        if not isinstance(user, str) or not _USER_NAME.fullmatch(user):
            raise AgentPrincipalError(
                f"agent user {user!r} is not a plain user name")
        if os.name != "posix":
            raise AgentPrincipalError("an agent principal requires POSIX")
        try:
            entry = pwd.getpwnam(user)
        except KeyError as exc:
            raise AgentPrincipalError(
                f"agent user {user!r} does not exist") from exc
        sudo = shutil.which("sudo")
        if sudo is None:
            raise AgentPrincipalError(
                "an agent principal requires sudo on PATH")
        return cls(user, uid=entry.pw_uid, gid=entry.pw_gid,
                   home=entry.pw_dir, shell=entry.pw_shell or "/bin/sh",
                   sudo=sudo, python=python or DEFAULT_PYTHON,
                   runner=runner)

    # ---- identity ---------------------------------------------------- #
    def identity(self) -> dict:
        """What a run journal binds: a resume as another user is refused."""
        return {"user": self.user, "uid": self.uid, "mechanism": MECHANISM}

    def describe(self) -> dict:
        """Provenance record of the separation."""
        evaluator = None
        if hasattr(os, "geteuid"):
            try:
                evaluator = pwd.getpwuid(os.geteuid()).pw_name
            except KeyError:
                evaluator = str(os.geteuid())
        return {"separated": True, "user": self.user, "uid": self.uid,
                "gid": self.gid, "evaluator_user": evaluator,
                "mechanism": MECHANISM, "launcher": [self.sudo, self.python],
                "workspace_transfer": "tar_copy_in_out",
                "per_turn_home": True}

    # ---- helper calls ------------------------------------------------ #
    def helper_argv(self, op: str) -> list[str]:
        return [self.sudo, "-n", "-u", self.user, "--", self.python,
                "-I", "-S", "-c", HELPER_SOURCE, op]

    def _spawn(self, op: str, *, stdout=subprocess.PIPE):
        try:
            return self._runner(
                self.helper_argv(op), cwd="/", env=dict(_SUDO_ENV),
                stdin=subprocess.PIPE, stdout=stdout,
                stderr=subprocess.PIPE, start_new_session=True)
        except OSError as exc:
            raise AgentPrincipalError(
                f"cannot start sudo for agent user {self.user}: {exc}") \
                from exc

    @staticmethod
    def _header(request: Mapping) -> bytes:
        return json.dumps(dict(request)).encode("utf-8") + b"\n"

    def _call(self, op: str, request: Mapping, *,
              timeout: float = _HELPER_TIMEOUT) -> dict:
        proc = self._spawn(op)
        try:
            stdout, stderr = proc.communicate(self._header(request),
                                              timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            proc.communicate()
            raise AgentPrincipalError(
                f"agent helper {op} timed out as {self.user}") from exc
        if proc.returncode != 0:
            raise AgentPrincipalError(self._failure(op, proc.returncode,
                                                    stderr))
        try:
            document = json.loads(stdout[:_MAX_HELPER_OUTPUT].decode())
        except (UnicodeDecodeError, ValueError) as exc:
            raise AgentPrincipalError(
                f"agent helper {op} returned no result") from exc
        if not isinstance(document, dict):
            raise AgentPrincipalError(f"agent helper {op} returned no result")
        return document

    def _failure(self, op: str, code, stderr: bytes | None) -> str:
        tail = (stderr or b"")[-2000:].decode("utf-8", "replace").strip()
        hint = ""
        if "password is required" in tail or "not allowed" in tail \
                or "may not run" in tail:
            hint = (f"; the evaluator needs the sudoers rule "
                    f"'{_evaluator_name()} ALL=({self.user}) NOPASSWD: "
                    f"{self.python}'")
        return (f"agent helper {op} failed as {self.user} (exit {code}): "
                f"{tail or 'no output'}{hint}")

    # ---- process control --------------------------------------------- #
    def launch(self, argv: Sequence[str], *, cwd: str,
               env: Mapping[str, str]) -> subprocess.Popen:
        """Start ``argv`` as the agent user; stdout/stderr are pipes.

        The child is a new session led by ``sudo``. Its argv carries only
        the helper; ``argv``, ``cwd`` and ``env`` travel over stdin.
        """
        proc = self._spawn("exec")
        try:
            proc.stdin.write(self._header(
                {"argv": list(argv), "cwd": str(cwd), "env": dict(env)}))
            proc.stdin.close()
        except OSError:
            # sudo refused before reading: the exit status and stderr tell.
            try:
                proc.stdin.close()
            except OSError:
                pass
        return proc

    def kill_all(self) -> dict:
        """SIGKILL every process of the agent user and wait until none runs."""
        with self._kill_lock:
            return self._call("kill", {}, timeout=60)

    # ---- environment -------------------------------------------------- #
    def environment(self, env: Mapping[str, str]) -> dict[str, str]:
        """The agent's environment: ``env`` re-homed to the agent user."""
        home = self._turn_home or self.home
        result = dict(env)
        result.update({"HOME": home, "USER": self.user,
                       "LOGNAME": self.user})
        result["SHELL"] = self.shell
        for name in _LOCATION_VARIABLES:
            value = result.get(name)
            if value is not None and not _inside(
                    os.path.normpath(value), self.home):
                del result[name]
        return result

    # ---- checks --------------------------------------------------------- #
    def probe(self, paths: Iterable[str | Path] = (),
              executables: Iterable[str | Path] = ()) -> dict:
        return self._call("probe", {
            "paths": [str(path) for path in paths],
            "executables": [str(path) for path in executables],
            "home": self.home, "credentials": list(CREDENTIAL_FILES)})

    def credentials(self) -> dict[str, bool]:
        """Which :data:`CREDENTIAL_FILES` exist in the agent's own home."""
        return dict(self.probe().get("credentials") or {})

    def preflight(self, private_paths: Iterable[str | Path], *,
                  executables: Iterable[str | Path] = ()) -> dict:
        """Fail closed unless the agent user is separated from ``private_paths``.

        ``private_paths`` are roots (files or directories); a bounded
        sample of each directory's contents is checked too. Returns the
        check record for provenance.
        """
        sample = sample_paths(private_paths)
        if not sample:
            raise AgentPrincipalError(
                "agent principal preflight has no private path to check")
        result = self.probe(sample, executables)
        problems: list[str] = []
        if result.get("uid") != self.uid:
            problems.append(f"helper ran as uid {result.get('uid')}, not "
                            f"{self.user} ({self.uid})")
        exposed = [path for path, facts in result.get("paths", {}).items()
                   if facts.get("readable") or facts.get("searchable")]
        if exposed:
            problems.append(
                f"agent user {self.user} can read evaluator material: "
                + ", ".join(sorted(exposed)[:10])
                + (f" (+{len(exposed) - 10} more)" if len(exposed) > 10
                   else ""))
        for path, ok in (result.get("executables") or {}).items():
            if not ok:
                problems.append(f"agent user {self.user} cannot execute "
                                f"{path}; install the agent CLI where that"
                                " user can run it")
        home = result.get("home") or {}
        if not home.get("owned") or not home.get("writable"):
            problems.append(f"agent user {self.user} does not own a "
                            f"writable home at {self.home}")
        if problems:
            raise AgentPrincipalError(
                "agent principal preflight failed: " + "; ".join(problems))
        return {"checked_paths": len(sample), "readable_paths": 0,
                "executables": sorted(result.get("executables") or {}),
                "home_owned": True}

    # ---- workspace -------------------------------------------------- #
    @contextmanager
    def checkout(self, workspace: str | Path) -> Iterator[str]:
        """Give the agent its own copy of ``workspace`` for one turn.

        Yields the agent-side path. On exit every agent process is killed,
        the tree is copied back into ``workspace`` (evaluator-owned) and
        the agent-side copy and per-turn home are removed. If the body
        raised, a failed copy-back leaves ``workspace`` as it was and the
        body's exception propagates; otherwise a failed copy-back raises.
        """
        if not self._lock.acquire(blocking=False):
            raise AgentPrincipalError(
                "agent principal already serves a turn; an agent user runs"
                " one turn at a time")
        workspace = Path(workspace)
        token = secrets.token_hex(8)
        names = {"workspace": "ws-" + token, "home": "home-" + token}
        try:
            with self._kill_lock:
                self.kill_all()  # nothing left over from an earlier turn
                agent_path = self._send(workspace, names)
            self._turn_home = os.path.join(self.work_base, names["home"])
            completed = False
            try:
                yield agent_path
                completed = True
            finally:
                self._turn_home = None
                with self._kill_lock:
                    try:
                        self.kill_all()
                        self._receive(workspace, names["workspace"])
                    except Exception:
                        if completed:
                            raise
                    finally:
                        try:
                            self._call("remove", {
                                "base": self.work_base,
                                "names": [names["workspace"],
                                          names["home"]]})
                        except AgentPrincipalError:
                            if completed:
                                raise
        finally:
            self._lock.release()

    def _send(self, workspace: Path, names: Mapping[str, str]) -> str:
        proc = self._spawn("unpack")
        errors: list[bytes] = []
        drain = threading.Thread(target=lambda: errors.append(
            proc.stderr.read()), daemon=True)
        drain.start()
        try:
            proc.stdin.write(self._header({
                "base": self.work_base, "persistent_home": self.home,
                "credentials": list(CREDENTIAL_FILES), **names}))
            with tarfile.open(fileobj=proc.stdin, mode="w|",
                              format=tarfile.PAX_FORMAT) as archive:
                archive.add(str(workspace), arcname=".",
                            filter=_anonymous)
            proc.stdin.close()
        except (OSError, tarfile.TarError):
            try:
                proc.stdin.close()
            except OSError:
                pass
        try:
            stdout = proc.stdout.read(_MAX_HELPER_OUTPUT)
            proc.wait(timeout=_HELPER_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            raise AgentPrincipalError("agent workspace copy timed out") \
                from exc
        drain.join(timeout=5)
        if proc.returncode != 0:
            raise AgentPrincipalError(self._failure(
                "unpack", proc.returncode, b"".join(errors)))
        try:
            document = json.loads(stdout.decode())
            return str(document["workspace"])
        except (UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
            raise AgentPrincipalError(
                "agent workspace copy returned no path") from exc

    def _receive(self, workspace: Path, name: str) -> None:
        proc = self._spawn("pack")
        errors: list[bytes] = []
        drain = threading.Thread(target=lambda: errors.append(
            proc.stderr.read()), daemon=True)
        drain.start()
        try:
            proc.stdin.write(self._header({"base": self.work_base,
                                           "workspace": name}))
            proc.stdin.close()
        except OSError:
            pass
        staging = Path(tempfile.mkdtemp(prefix=".agent-return-",
                                        dir=workspace.parent))
        try:
            try:
                receive_tree(proc.stdout, staging)
            finally:
                proc.stdout.close()
                try:
                    proc.wait(timeout=_HELPER_TIMEOUT)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                drain.join(timeout=5)
            if proc.returncode != 0:
                raise AgentPrincipalError(self._failure(
                    "pack", proc.returncode, b"".join(errors)))
            remove_tree(workspace)
            os.rename(staging, workspace)
        finally:
            if staging.exists():
                remove_tree(staging)


def _evaluator_name() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except (KeyError, AttributeError):
        return "EVALUATOR"


def _anonymous(member: tarfile.TarInfo) -> tarfile.TarInfo:
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    return member


def sample_paths(roots: Iterable[str | Path], *,
                 per_root: int = 64) -> list[str]:
    """Each root plus up to ``per_root`` entries below it (files first)."""
    sample: list[str] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        text = str(path)
        if text not in seen and len(sample) < _MAX_PROBE_PATHS:
            seen.add(text)
            sample.append(text)

    for raw in roots:
        if raw is None:
            continue
        root = Path(raw).absolute()
        if not os.path.lexists(root):
            continue
        add(root)
        if not root.is_dir() or root.is_symlink():
            continue
        files: list[Path] = []
        dirs: list[Path] = []
        for current, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                files.append(Path(current) / name)
            for name in dirnames:
                dirs.append(Path(current) / name)
            if len(files) >= per_root:
                break
        for path in (files + dirs)[:per_root]:
            add(path)
    return sample


def remove_tree(path: Path) -> None:
    """Remove an evaluator-owned tree, read-only directories included."""
    def retry(function, name, _info):
        parent = os.path.dirname(name)
        try:
            os.chmod(parent, 0o700)
            if os.path.isdir(name) and not os.path.islink(name):
                os.chmod(name, 0o700)
        except OSError:
            pass
        function(name)
    if os.path.lexists(path):
        if os.path.isdir(path) and not os.path.islink(path):
            os.chmod(path, 0o700)
            shutil.rmtree(path, onerror=retry)
        else:
            os.unlink(path)


def _member_path(name: str) -> PurePosixPath | None:
    """The normalized relative path of a tar member; ``None`` for the root."""
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if name.startswith("/") or any(part == ".." for part in parts):
        raise AgentPrincipalError(f"agent tree has an unsafe name: {name!r}")
    return PurePosixPath(*parts) if parts else None


def receive_tree(stream, destination: Path, *,
                 max_bytes: int = MAX_RETURN_BYTES,
                 max_entries: int = MAX_RETURN_ENTRIES) -> None:
    """Unpack an untrusted tar stream into the empty ``destination``.

    Every entry is created fresh by this process under ``destination``;
    a parent must already be a real directory created here, so a symlink
    in the archive is stored as a link and never followed. Hard links
    become copies. Devices, FIFOs and other types are refused. Set-id and
    sticky bits are dropped; directory modes are applied last.
    """
    destination = Path(destination)
    created: dict[PurePosixPath, str] = {}
    dir_modes: list[tuple[Path, int]] = []
    root_mode: int | None = None
    total = entries = 0
    try:
        archive = tarfile.open(fileobj=stream, mode="r|")
    except tarfile.TarError as exc:
        raise AgentPrincipalError(f"agent tree is not an archive: {exc}") \
            from exc
    with archive:
        try:
            for member in archive:
                entries += 1
                if entries > max_entries:
                    raise AgentPrincipalError(
                        "agent tree has too many entries")
                relative = _member_path(member.name)
                mode = stat.S_IMODE(member.mode) & 0o777
                if relative is None:
                    if not member.isdir():
                        raise AgentPrincipalError(
                            "agent tree root is not a directory")
                    root_mode = mode
                    continue
                if relative in created:
                    raise AgentPrincipalError(
                        f"agent tree repeats {relative}")
                parent = relative.parent
                if parent != PurePosixPath(".") and \
                        created.get(parent) != "dir":
                    raise AgentPrincipalError(
                        f"agent tree entry {relative} has no directory")
                target = destination / relative
                if member.isdir():
                    os.mkdir(target, 0o700)
                    dir_modes.append((target, mode))
                    created[relative] = "dir"
                elif member.isreg():
                    total += member.size
                    if total > max_bytes:
                        raise AgentPrincipalError("agent tree is too large")
                    source = archive.extractfile(member)
                    _write_new(target, source, mode)
                    created[relative] = "file"
                elif member.issym():
                    os.symlink(member.linkname, target)
                    created[relative] = "link"
                elif member.islnk():
                    linked = _member_path(member.linkname)
                    if linked is None or created.get(linked) != "file":
                        raise AgentPrincipalError(
                            f"agent tree hard link {relative} is unsafe")
                    source_path = destination / linked
                    total += source_path.stat().st_size
                    if total > max_bytes:
                        raise AgentPrincipalError("agent tree is too large")
                    with open(source_path, "rb") as source:
                        _write_new(target, source, mode)
                    created[relative] = "file"
                else:
                    raise AgentPrincipalError(
                        f"agent tree entry {relative} is not a file,"
                        " directory or symlink")
        except tarfile.TarError as exc:
            raise AgentPrincipalError(f"agent tree is truncated: {exc}") \
                from exc
    if root_mode is None:
        raise AgentPrincipalError("agent tree has no root directory")
    for path, mode in reversed(dir_modes):
        os.chmod(path, mode)
    os.chmod(destination, root_mode)


def _write_new(target: Path, source, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        if source is not None:
            shutil.copyfileobj(source, handle, 1 << 20)
    os.chmod(target, mode)


@contextmanager
def agent_workspace(principal: AgentPrincipal | None,
                    workspace: str | Path) -> Iterator[str]:
    """The workspace path the agent uses: its own copy under a principal."""
    if principal is None:
        yield str(workspace)
        return
    with principal.checkout(workspace) as path:
        yield path


def resolve_principal(agent_user: str | None = None,
                      principal: AgentPrincipal | None = None
                      ) -> AgentPrincipal | None:
    """``principal`` if given, else one resolved from ``agent_user``."""
    if principal is not None:
        return principal
    if agent_user is None:
        return None
    return AgentPrincipal.resolve(agent_user)


__all__ = ["AgentPrincipal", "AgentPrincipalError", "CREDENTIAL_FILES",
           "DEFAULT_PYTHON", "HELPER_SOURCE", "MAX_RETURN_BYTES",
           "MAX_RETURN_ENTRIES", "MECHANISM", "agent_workspace",
           "receive_tree", "remove_tree", "resolve_principal",
           "sample_paths"]
