"""Test-suite configuration: platform scope.

Platform support (docs/v3/SECURITY_BOUNDARIES_V3_3.md): Linux and macOS run
the whole suite. Windows is supported for the core learner and CLI only; the
v3 evaluator, sandbox and study layer under tests/v3 relies on POSIX process,
permission and file semantics and on the Linux sandbox, so it is not
collected on Windows. The run header says so, so the omission is never
silent.
"""
from __future__ import annotations

import os

_V3 = os.path.realpath(os.path.join(os.path.dirname(__file__), "v3"))
POSIX_ONLY_NOTE = ("tests/v3 not collected: the v3 evaluator, sandbox and "
                   "study layer is POSIX-only on this release "
                   "(docs/v3/SECURITY_BOUNDARIES_V3_3.md)")


def pytest_ignore_collect(collection_path, config):
    if os.name == "nt" and os.path.realpath(os.fspath(collection_path)) == _V3:
        return True
    return None


def pytest_report_header(config):
    if os.name == "nt":
        return POSIX_ONLY_NOTE
    return None
