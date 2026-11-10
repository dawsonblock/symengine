"""Apply the SIS seccomp denylist, then exec the evaluated command.

This file is copied into a worker-owned read-only directory and invoked
inside the bubblewrap sandbox, after namespace and mount setup. It
applies a BPF filter to itself, then ``execvpe``s the real command, so
the filter is inherited by the command and every descendant.

The filter denies syscalls that can escape or subvert the containment:
mount/umount/pivot_root, namespace changes, ptrace, kernel module and
key management, BPF/perf, process memory access, handle-based file
access, and host identity/time changes. It does not deny fork/clone,
execve, sockets, or ordinary file access; the network namespace and
cgroup limits bound those.

No part of this file claims containment. It is one layer of the worker;
the isolator attests the properties the worker enforced.
"""
from __future__ import annotations

import ctypes
import os
import platform
import sys

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
EPERM = 1

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

_DENY_X86_64 = (
    101,   # ptrace
    155,   # pivot_root
    163,   # acct
    164,   # settimeofday
    165,   # mount
    166,   # umount2
    167,   # swapon
    168,   # swapoff
    169,   # reboot
    170,   # sethostname
    171,   # setdomainname
    172,   # iopl
    173,   # ioperm
    175,   # init_module
    176,   # delete_module
    227,   # clock_settime
    246,   # kexec_load
    248,   # add_key
    249,   # request_key
    250,   # keyctl
    272,   # unshare
    298,   # perf_event_open
    300,   # fanotify_init
    303,   # name_to_handle_at
    304,   # open_by_handle_at
    308,   # setns
    310,   # process_vm_readv
    311,   # process_vm_writev
    313,   # finit_module
    320,   # kexec_file_load
    321,   # bpf
    323,   # userfaultfd
)

_DENY_AARCH64 = (
    39,    # umount2
    40,    # mount
    41,    # pivot_root
    89,    # acct
    97,    # unshare
    104,   # kexec_load
    105,   # init_module
    106,   # delete_module
    112,   # clock_settime
    117,   # ptrace
    142,   # reboot
    161,   # sethostname
    162,   # setdomainname
    170,   # settimeofday
    217,   # add_key
    218,   # request_key
    219,   # keyctl
    224,   # swapon
    225,   # swapoff
    241,   # perf_event_open
    262,   # fanotify_init
    264,   # name_to_handle_at
    265,   # open_by_handle_at
    268,   # setns
    270,   # process_vm_readv
    271,   # process_vm_writev
    273,   # finit_module
    280,   # bpf
    282,   # userfaultfd
    294,   # kexec_file_load
)


class SeccompUnavailable(RuntimeError):
    """The platform cannot apply the seccomp filter."""


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(SockFilter)),
    ]


def detect_arch(machine: str | None = None) -> str:
    value = (machine or platform.machine()).lower()
    if value in ("x86_64", "amd64"):
        return "x86_64"
    if value in ("aarch64", "arm64"):
        return "aarch64"
    raise SeccompUnavailable(f"unsupported_arch:{value}")


def build_filter(arch: str) -> list[SockFilter]:
    """Build the BPF program: arch check, syscall denylist, allow."""
    if arch == "x86_64":
        audit_arch, denied = AUDIT_ARCH_X86_64, _DENY_X86_64
    elif arch == "aarch64":
        audit_arch, denied = AUDIT_ARCH_AARCH64, _DENY_AARCH64
    else:
        raise SeccompUnavailable(f"unsupported_arch:{arch}")
    count = len(denied)
    allow_index = 3 + count
    kill_index = allow_index + 1
    deny_index = kill_index + 1

    def ins(code, jt, jf, k):
        return SockFilter(code, jt, jf, k)

    filters = [
        ins(0x20, 0, 0, 4),                     # ld [4]  (arch)
        ins(0x15, 0, kill_index - 2, audit_arch),  # jeq arch -> next, else kill
        ins(0x20, 0, 0, 0),                     # ld [0]  (syscall nr)
    ]
    for position, number in enumerate(denied):
        filters.append(
            ins(0x15, deny_index - (4 + position), 0, number))
    filters.append(ins(0x06, 0, 0, SECCOMP_RET_ALLOW))
    filters.append(ins(0x06, 0, 0, SECCOMP_RET_KILL_PROCESS))
    filters.append(ins(0x06, 0, 0, SECCOMP_RET_ERRNO | EPERM))
    return filters


def apply_filter(arch: str | None = None) -> None:
    """Install the filter on the current process; never returns on failure."""
    if not sys.platform.startswith("linux"):
        raise SeccompUnavailable("linux_required")
    filters = build_filter(arch or detect_arch())
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p,
        ctypes.c_ulong, ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if prctl(PR_SET_NO_NEW_PRIVS, 1, None, 0, 0) != 0:
        raise SeccompUnavailable(
            f"no_new_privs_failed:{ctypes.get_errno()}")
    array = (SockFilter * len(filters))(*filters)
    program = SockFprog(
        len(filters), ctypes.cast(array, ctypes.POINTER(SockFilter)))
    if prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
             ctypes.byref(program), 0, 0) != 0:
        raise SeccompUnavailable(f"seccomp_failed:{ctypes.get_errno()}")


def main(argv: list[str] | None = None) -> int:
    command = list(sys.argv[1:] if argv is None else argv)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        print("seccomp_exec: missing command", file=sys.stderr)
        return 2
    try:
        apply_filter()
    except SeccompUnavailable as exc:
        print(f"seccomp_exec: {exc}", file=sys.stderr)
        return 126
    try:
        os.execvpe(command[0], command, os.environ)
    except OSError as exc:
        print(f"seccomp_exec: exec failed: {exc}", file=sys.stderr)
        return 127
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
