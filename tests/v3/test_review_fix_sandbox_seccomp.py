"""Run the generated seccomp BPF program in a small interpreter."""
from __future__ import annotations

import platform
import struct
import subprocess
import sys
import unittest

from sis.v3.seccomp_exec import (
    AUDIT_ARCH_AARCH64,
    AUDIT_ARCH_X86_64,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS,
    build_filter,
)

EPERM = SECCOMP_RET_ERRNO | 1
ENOSYS = SECCOMP_RET_ERRNO | 38

CLONE_NEWUSER = 0x10000000
CLONE_NEWNS = 0x00020000
CLONE_NEWNET = 0x40000000
SIGCHLD = 17
# glibc's fork(): CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD
FORK_FLAGS = 0x01200000 | SIGCHLD
# pthread_create flags
THREAD_FLAGS = 0x003D0F00


def run(program, *, arch: int, nr: int, args=(0,) * 6) -> int:
    """Evaluate classic BPF over a little-endian ``seccomp_data``."""
    data = struct.pack("<iIQ6Q", nr, arch, 0, *(list(args) + [0] * 6)[:6])
    acc = 0
    pc = 0
    for _ in range(10_000):
        ins = program[pc]
        code, jt, jf, k = ins.code, ins.jt, ins.jf, ins.k
        if code == 0x20:            # ld [k]
            acc = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif code == 0x15:          # jeq k
            pc += 1 + (jt if acc == k else jf)
        elif code == 0x45:          # jset k
            pc += 1 + (jt if acc & k else jf)
        elif code == 0x06:          # ret k
            return k
        else:
            raise AssertionError(f"unexpected opcode {code:#x}")
    raise AssertionError("program did not terminate")


class SeccompProgramTests(unittest.TestCase):
    def setUp(self):
        self.x86 = build_filter("x86_64")
        self.arm = build_filter("aarch64")

    def x86_run(self, nr, *args):
        return run(self.x86, arch=AUDIT_ARCH_X86_64, nr=nr, args=args or (0,) * 6)

    def arm_run(self, nr, *args):
        return run(self.arm, arch=AUDIT_ARCH_AARCH64, nr=nr, args=args or (0,) * 6)

    def test_wrong_architecture_is_killed(self):
        self.assertEqual(
            run(self.x86, arch=0x40000003, nr=0), SECCOMP_RET_KILL_PROCESS)

    def test_ordinary_syscalls_are_allowed(self):
        for nr in (0, 1, 2, 59, 57, 231):  # read write open execve fork exit_group
            self.assertEqual(self.x86_run(nr), SECCOMP_RET_ALLOW, nr)
        for nr in (63, 64, 221, 94):  # read write execve exit_group
            self.assertEqual(self.arm_run(nr), SECCOMP_RET_ALLOW, nr)

    def test_existing_denials_still_hold(self):
        for nr in (101, 165, 272, 308, 321):  # ptrace mount unshare setns bpf
            self.assertEqual(self.x86_run(nr), EPERM, nr)
        for nr in (117, 40, 97, 268, 280):
            self.assertEqual(self.arm_run(nr), EPERM, nr)

    def test_x32_abi_is_denied(self):
        # x32 aliases (e.g. 0x40000000 | 101 ptrace, | 165 mount) would
        # otherwise miss the native-number denylist.
        for nr in (0x40000000 | 101, 0x40000000 | 165, 0x40000000 | 0,
                   0x40000000 | 520):
            self.assertEqual(self.x86_run(nr), EPERM, hex(nr))

    def test_new_mount_api_and_io_uring_are_denied(self):
        for nr in (425, 426, 427, 428, 429, 430, 431, 432, 433, 442):
            self.assertEqual(self.x86_run(nr), EPERM, nr)
            self.assertEqual(self.arm_run(nr), EPERM, nr)

    def test_clone3_reports_enosys_so_libc_falls_back(self):
        self.assertEqual(self.x86_run(435), ENOSYS)
        self.assertEqual(self.arm_run(435), ENOSYS)

    def test_clone_with_namespace_flags_is_denied(self):
        for flags in (CLONE_NEWUSER | SIGCHLD, CLONE_NEWNS, CLONE_NEWNET,
                      CLONE_NEWUSER | CLONE_NEWNS | SIGCHLD):
            self.assertEqual(self.x86_run(56, flags, 0, 0, 0, 0, 0),
                             EPERM, hex(flags))
            self.assertEqual(self.arm_run(220, flags, 0, 0, 0, 0, 0),
                             EPERM, hex(flags))

    def test_plain_fork_and_thread_clone_are_allowed(self):
        for flags in (FORK_FLAGS, THREAD_FLAGS, SIGCHLD):
            self.assertEqual(self.x86_run(56, flags, 0, 0, 0, 0, 0),
                             SECCOMP_RET_ALLOW, hex(flags))
            self.assertEqual(self.arm_run(220, flags, 0, 0, 0, 0, 0),
                             SECCOMP_RET_ALLOW, hex(flags))

    def test_aarch64_has_no_x32_check(self):
        # 0x40000000 is not an ABI bit on aarch64; an out-of-range number
        # falls through the denylist and the kernel returns ENOSYS.
        self.assertEqual(self.arm_run(0x40000000 | 1), SECCOMP_RET_ALLOW)


_KERNEL_PROBE = r"""
import ctypes, os, subprocess, sys, threading
from sis.v3.seccomp_exec import apply_filter
apply_filter()
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
results = {}
pid = os.fork()
if pid == 0:
    os._exit(0)
os.waitpid(pid, 0)
thread = threading.Thread(target=lambda: None)
thread.start(); thread.join()
results["subprocess"] = subprocess.run(["true"]).returncode
clone = 56 if sys.argv[1] == "x86_64" else 220
ctypes.set_errno(0)
results["clone_newuser"] = (
    libc.syscall(clone, 0x10000000 | 17, 0, 0, 0, 0), ctypes.get_errno())
ctypes.set_errno(0)
results["clone3"] = (libc.syscall(435, 0, 0), ctypes.get_errno())
ctypes.set_errno(0)
results["io_uring_setup"] = (libc.syscall(425, 1, 0), ctypes.get_errno())
ctypes.set_errno(0)
results["fsopen"] = (libc.syscall(430, b"tmpfs", 0), ctypes.get_errno())
print(repr(results))
"""


@unittest.skipUnless(
    sys.platform.startswith("linux")
    and platform.machine().lower() in ("x86_64", "amd64", "aarch64", "arm64"),
    "the real filter is applied only on Linux x86_64/aarch64")
class SeccompKernelTests(unittest.TestCase):
    def test_filter_on_the_running_kernel(self):
        arch = ("x86_64" if platform.machine().lower() in ("x86_64", "amd64")
                else "aarch64")
        completed = subprocess.run(
            [sys.executable, "-c", _KERNEL_PROBE, arch],
            capture_output=True, text=True, timeout=60)
        if "seccomp_failed" in completed.stderr or "no_new_privs" in completed.stderr:
            self.skipTest("kernel refuses seccomp here")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        import ast
        results = ast.literal_eval(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(results["subprocess"], 0)
        self.assertEqual(results["clone_newuser"], (-1, 1))
        self.assertEqual(results["clone3"], (-1, 38))
        self.assertEqual(results["io_uring_setup"], (-1, 1))
        self.assertEqual(results["fsopen"], (-1, 1))


if __name__ == "__main__":
    unittest.main()
