#!/usr/bin/env python3
"""Derive ``docker/sandbox/seccomp.json`` from Docker's default profile.

The evaluator sandbox profile is an allowlist (default action
``SCMP_ACT_ERRNO``/EPERM). It starts from the unconditional allow rule of
Moby's default profile at a pinned tag, removes the syscalls a Python
test workload in a capability-free, network-less container never needs
(the ``REMOVED`` table records why each one goes), drops every rule that
Docker only enables for a capability the sandbox does not hold, and keeps
the argument-filtered rules for ``socket``, ``personality`` and ``clone``.

The upstream file is an input, not a dependency: fetch it once, check its
digest against ``UPSTREAM_SHA256``, then regenerate or check:

    curl -sSfL -o /tmp/moby-default.json \\
      https://raw.githubusercontent.com/moby/moby/v27.3.1/profiles/seccomp/default.json
    python3 tools/derive_sandbox_seccomp.py --upstream /tmp/moby-default.json
    python3 tools/derive_sandbox_seccomp.py --upstream /tmp/moby-default.json --check

Without ``--upstream`` the tool only validates the committed profile's
invariants (deny by default; none of ``FORBIDDEN`` allowed), which is what
the test suite runs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "docker" / "sandbox" / "seccomp.json"
UPSTREAM_URL = ("https://raw.githubusercontent.com/moby/moby/v27.3.1/"
                "profiles/seccomp/default.json")
UPSTREAM_SHA256 = (
    "9c1025c88ccaa517b648da571961838744ea2137f176bfe6a48b21294cae9c76")

#: Unconditionally allowed upstream, removed here, with the reason.
REMOVED = {
    # Kernel AIO: CPython and pytest never use it; a long CVE history.
    "io_setup": "kernel AIO unused by Python workloads",
    "io_submit": "kernel AIO unused by Python workloads",
    "io_cancel": "kernel AIO unused by Python workloads",
    "io_destroy": "kernel AIO unused by Python workloads",
    "io_getevents": "kernel AIO unused by Python workloads",
    "io_pgetevents": "kernel AIO unused by Python workloads",
    "io_pgetevents_time64": "kernel AIO unused by Python workloads",
    # Handle-based opens bypass path resolution.
    "name_to_handle_at": "file handles are not needed in a workspace",
    "fanotify_mark": "fanotify_init needs CAP_SYS_ADMIN anyway",
    "remap_file_pages": "deprecated; emulated and rarely exercised",
    "vmsplice": "page-gifting splice with a CVE history; unused by CPython",
    "memfd_secret": "secret memory areas are not needed",
    # Time adjustment is read-only without CAP_SYS_TIME, and unneeded.
    "adjtimex": "clock adjustment is not a test-workload need",
    "clock_adjtime": "clock adjustment is not a test-workload need",
    "clock_adjtime64": "clock adjustment is not a test-workload need",
    # POSIX and SysV message queues: multiprocessing uses neither.
    "mq_getsetattr": "POSIX message queues are unused",
    "mq_notify": "POSIX message queues are unused",
    "mq_open": "POSIX message queues are unused",
    "mq_timedreceive": "POSIX message queues are unused",
    "mq_timedreceive_time64": "POSIX message queues are unused",
    "mq_timedsend": "POSIX message queues are unused",
    "mq_timedsend_time64": "POSIX message queues are unused",
    "mq_unlink": "POSIX message queues are unused",
    "msgctl": "SysV message queues are unused",
    "msgget": "SysV message queues are unused",
    "msgrcv": "SysV message queues are unused",
    "msgsnd": "SysV message queues are unused",
    # The 32-bit multiplexers would bypass the socket(2) family filter.
    "socketcall": "multiplexer that bypasses the socket family filter",
    "ipc": "multiplexer for SysV IPC on 32-bit ABIs",
    # Identity changes: the container principal is fixed at launch and
    # no-new-privileges plus zero capabilities make them pointless.
    "setuid": "the principal is fixed at launch",
    "setuid32": "the principal is fixed at launch",
    "setgid": "the principal is fixed at launch",
    "setgid32": "the principal is fixed at launch",
    "setreuid": "the principal is fixed at launch",
    "setreuid32": "the principal is fixed at launch",
    "setregid": "the principal is fixed at launch",
    "setregid32": "the principal is fixed at launch",
    "setresuid": "the principal is fixed at launch",
    "setresuid32": "the principal is fixed at launch",
    "setresgid": "the principal is fixed at launch",
    "setresgid32": "the principal is fixed at launch",
    "setfsuid": "the principal is fixed at launch",
    "setfsuid32": "the principal is fixed at launch",
    "setfsgid": "the principal is fixed at launch",
    "setfsgid32": "the principal is fixed at launch",
    "setgroups": "the principal is fixed at launch",
    "setgroups32": "the principal is fixed at launch",
}

#: Never allowed by the derived profile; the tests enforce this list.
FORBIDDEN = (
    "ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
    "pidfd_getfd", "process_madvise",
    "mount", "umount", "umount2", "mount_setattr", "move_mount",
    "open_tree", "fsopen", "fsconfig", "fsmount", "fspick", "pivot_root",
    "chroot", "unshare", "setns",
    "bpf", "perf_event_open", "userfaultfd", "kexec_load",
    "kexec_file_load", "init_module", "finit_module", "delete_module",
    "keyctl", "add_key", "request_key", "syslog", "acct", "reboot",
    "swapon", "swapoff", "open_by_handle_at", "name_to_handle_at",
    "quotactl", "quotactl_fd", "iopl", "ioperm", "modify_ldt",
    "settimeofday", "clock_settime", "sethostname", "setdomainname",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "lookup_dcookie", "fanotify_init", "vhangup", "socketcall",
    "setuid", "setresuid", "setgroups", "vmsplice",
)

#: Argument filters: socket(2) families the workload may open.
SOCKET_FAMILIES = {"AF_UNIX": 1, "AF_INET": 2, "AF_INET6": 10}
#: CLONE_NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET (Docker's mask).
CLONE_NAMESPACE_MASK = 2114060288


def derive(upstream: dict) -> dict:
    base = [rule for rule in upstream["syscalls"]
            if set(rule) == {"names", "action"}
            and rule["action"] == "SCMP_ACT_ALLOW"]
    if len(base) != 1:
        raise ValueError("upstream profile has no single unconditional rule")
    missing = sorted(set(REMOVED) - set(base[0]["names"]))
    if missing:
        raise ValueError(f"REMOVED names absent upstream: {missing}")
    allowed = sorted(name for name in base[0]["names"]
                     if name not in REMOVED)
    clash = sorted(set(allowed) & set(FORBIDDEN))
    if clash:
        raise ValueError(f"upstream allows forbidden syscalls: {clash}")
    rules: list[dict] = [{
        "names": allowed,
        "action": "SCMP_ACT_ALLOW",
        "comment": "Moby v27.3.1 unconditional allowlist minus REMOVED",
    }]
    for family, number in SOCKET_FAMILIES.items():
        rules.append({
            "names": ["socket"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{"index": 0, "value": number, "op": "SCMP_CMP_EQ"}],
            "comment": f"socket({family}) only; no netlink, packet or vsock",
        })
    for rule in upstream["syscalls"]:
        if rule.get("names") == ["personality"]:
            rules.append({key: rule[key] for key in ("names", "action", "args")})
    rules.append({
        "names": ["arch_prctl"], "action": "SCMP_ACT_ALLOW",
        "includes": {"arches": ["amd64", "x32"]},
        "comment": "TLS setup on x86-64",
    })
    rules.append({
        "names": ["arm_fadvise64_64", "arm_sync_file_range",
                  "sync_file_range2", "breakpoint", "cacheflush", "set_tls"],
        "action": "SCMP_ACT_ALLOW",
        "includes": {"arches": ["arm", "arm64"]},
        "comment": "ARM runtime helpers",
    })
    rules.append({
        "names": ["clone"], "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 0, "value": CLONE_NAMESPACE_MASK,
                  "op": "SCMP_CMP_MASKED_EQ"}],
        "comment": "threads and processes, never new namespaces",
    })
    rules.append({
        "names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38,
        "comment": "ENOSYS: clone3 flags live in memory and cannot be "
                   "filtered; libc falls back to clone",
    })
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "archMap": [
            {"architecture": "SCMP_ARCH_X86_64",
             "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]},
            {"architecture": "SCMP_ARCH_AARCH64",
             "subArchitectures": ["SCMP_ARCH_ARM"]},
        ],
        "syscalls": rules,
    }


def render(profile: dict) -> bytes:
    return (json.dumps(profile, indent=2, sort_keys=True) + "\n").encode()


def allowed_names(profile: dict) -> set[str]:
    """Names any ALLOW rule permits, with or without argument filters."""
    names: set[str] = set()
    for rule in profile.get("syscalls", ()):
        if rule.get("action") == "SCMP_ACT_ALLOW":
            names.update(rule.get("names", ()))
    return names


def check_invariants(profile: dict) -> list[str]:
    problems = []
    if profile.get("defaultAction") != "SCMP_ACT_ERRNO":
        problems.append("default action must be SCMP_ACT_ERRNO")
    allowed = allowed_names(profile)
    for name in FORBIDDEN:
        if name in allowed:
            problems.append(f"forbidden syscall allowed: {name}")
    for rule in profile.get("syscalls", ()):
        if rule.get("names") == ["socket"] and not rule.get("args"):
            problems.append("socket(2) must be filtered by family")
        if rule.get("names") == ["clone"] and rule.get(
                "action") == "SCMP_ACT_ALLOW" and not rule.get("args"):
            problems.append("clone(2) must be filtered by namespace flags")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--upstream", type=Path, default=None,
                        help=f"Moby default profile ({UPSTREAM_URL})")
    parser.add_argument("--output", type=Path, default=PROFILE)
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed profile differs from"
                             " the derivation")
    args = parser.parse_args(argv)

    if args.upstream is None:
        profile = json.loads(args.output.read_text())
        problems = check_invariants(profile)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    raw = args.upstream.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != UPSTREAM_SHA256:
        print(f"upstream digest {digest} != pinned {UPSTREAM_SHA256}",
              file=sys.stderr)
        return 2
    derived = render(derive(json.loads(raw)))
    problems = check_invariants(json.loads(derived))
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    if args.check:
        if args.output.read_bytes() != derived:
            print(f"{args.output} differs from the derivation",
                  file=sys.stderr)
            return 1
        print(f"{args.output} matches the derivation")
        return 0
    args.output.write_bytes(derived)
    print(f"wrote {args.output} sha256={hashlib.sha256(derived).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
