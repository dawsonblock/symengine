"""Apply the SIS seccomp denylist, then exec the evaluated command.

This file is copied into a worker-owned read-only directory and invoked
inside the bubblewrap sandbox, after namespace and mount setup. It
applies a BPF filter to itself, then ``execvpe``s the real command, so
the filter is inherited by the command and every descendant.

The filter denies syscalls that can escape or subvert the containment:
mount/umount/pivot_root and the new mount API (fsopen, fsconfig,
fsmount, fspick, move_mount, open_tree, mount_setattr), namespace
changes (unshare, setns, and ``clone`` with any ``CLONE_NEW*`` flag),
io_uring, ptrace, kernel module and key management, BPF/perf, process
memory access, handle-based file access, and host identity/time
changes. On x86_64 every x32-ABI syscall (``nr & 0x40000000``) is
denied, so the x32 aliases cannot bypass the native-number denylist.
``clone3`` passes its flags in memory, which a seccomp filter cannot
inspect, so it fails with ENOSYS; libc then falls back to ``clone``,
whose flags are checked. It does not deny fork/clone, execve, sockets,
or ordinary file access; the network namespace and cgroup limits bound
those.

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
ENOSYS = 38

#: x32 ABI syscalls on x86_64 carry this bit in the syscall number.
X32_SYSCALL_BIT = 0x40000000
#: ``CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC |
#: CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET``. ``CLONE_NEWTIME``
#: (0x80) overlaps the exit-signal byte of ``clone`` and is only valid
#: for ``clone3``/``unshare``, both denied outright.
CLONE_NAMESPACE_FLAGS = 0x7E020000

# Syscall numbers from 424 upward are shared by every architecture.
_DENY_COMMON = (
    425,   # io_uring_setup
    426,   # io_uring_enter
    427,   # io_uring_register
    428,   # open_tree
    429,   # move_mount
    430,   # fsopen
    431,   # fsconfig
    432,   # fsmount
    433,   # fspick
    442,   # mount_setattr
)
CLONE3 = 435
_CLONE = {"x86_64": 56, "aarch64": 220}

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
    """Build the BPF program.

    Order: architecture check (kill on mismatch), x32 rejection on
    x86_64, the syscall denylist (EPERM), ``clone3`` (ENOSYS), ``clone``
    with namespace flags (EPERM), allow. The program always ends with
    the ``ALLOW``, ``KILL_PROCESS`` and ``ERRNO|EPERM`` returns.
    """
    if arch == "x86_64":
        audit_arch, denied = AUDIT_ARCH_X86_64, _DENY_X86_64
    elif arch == "aarch64":
        audit_arch, denied = AUDIT_ARCH_AARCH64, _DENY_AARCH64
    else:
        raise SeccompUnavailable(f"unsupported_arch:{arch}")
    denied = tuple(denied) + _DENY_COMMON
    # Symbolic program: jump targets are labels resolved below.
    program: list[tuple] = [
        (0x20, None, None, 4),                  # ld [4]  (arch)
        (0x15, None, "kill", audit_arch),       # jeq arch, else kill
        (0x20, None, None, 0),                  # ld [0]  (syscall nr)
    ]
    if arch == "x86_64":
        program.append((0x45, "deny", None, X32_SYSCALL_BIT))  # jset x32
    for number in denied:
        program.append((0x15, "deny", None, number))
    program.append((0x15, "enosys", None, CLONE3))
    program.append((0x15, None, "allow", _CLONE[arch]))  # not clone: allow
    program.append((0x20, None, None, 16))   # ld args[0] (low 32 bits)
    program.append((0x45, "deny", "allow", CLONE_NAMESPACE_FLAGS))
    labels = {}
    program.append(("label", "enosys"))
    program.append((0x06, None, None, SECCOMP_RET_ERRNO | ENOSYS))
    program.append(("label", "allow"))
    program.append((0x06, None, None, SECCOMP_RET_ALLOW))
    program.append(("label", "kill"))
    program.append((0x06, None, None, SECCOMP_RET_KILL_PROCESS))
    program.append(("label", "deny"))
    program.append((0x06, None, None, SECCOMP_RET_ERRNO | EPERM))
    instructions = []
    for item in program:
        if item[0] == "label":
            labels[item[1]] = len(instructions)
        else:
            instructions.append(item)

    def offset(index: int, target) -> int:
        if target is None:
            return 0
        jump = labels[target] - (index + 1)
        if not 0 <= jump <= 255:
            raise SeccompUnavailable("filter_jump_out_of_range")
        return jump

    return [
        SockFilter(code, offset(index, jt), offset(index, jf), k)
        for index, (code, jt, jf, k) in enumerate(instructions)
    ]


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
