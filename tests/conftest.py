"""Test-suite configuration: pinned pytest and platform scope.

Pinned pytest: the evaluator refuses any pytest other than the pinned
``EvaluationRuntimeProfile.pytest_version`` (``runtime_pin_mismatch``), so
under another pytest the evaluator tests fail by design. The session
therefore stops before collection with one message naming the required
version and how to install it. ``SIS_ALLOW_UNPINNED_PYTEST=1`` runs the
suite anyway, for compatibility checks against a newer pytest.

Platform support (docs/v3/SECURITY_BOUNDARIES_V3_3.md): Linux and macOS run
the whole suite. Windows is supported for the core learner and CLI only; the
v3 evaluator, sandbox and study layer under tests/v3 relies on POSIX process,
permission and file semantics and on the Linux sandbox, so it is not
collected on Windows. The run says so (in the header, and in the terminal
summary, which pytest prints even under -q), so the omission is never silent.
"""
from __future__ import annotations

import os

_V3 = os.path.realpath(os.path.join(os.path.dirname(__file__), "v3"))
POSIX_ONLY_NOTE = ("tests/v3 not collected: the v3 evaluator, sandbox and "
                   "study layer is POSIX-only on this release "
                   "(docs/v3/SECURITY_BOUNDARIES_V3_3.md)")
ALLOW_UNPINNED_ENV = "SIS_ALLOW_UNPINNED_PYTEST"
# pytest's own exit code for a usage error.
PIN_MISMATCH_EXIT = 4


def required_pytest_version() -> str:
    """The evaluator's pinned pytest; imported lazily so it has one home."""
    from sis.v3.evaluation_runtime import EvaluationRuntimeProfile
    return EvaluationRuntimeProfile().pytest_version


def installed_pytest_version() -> str:
    """What the evaluator's ``assert_pinned`` compares against the pin."""
    import importlib.metadata
    try:
        return importlib.metadata.version("pytest")
    except importlib.metadata.PackageNotFoundError:
        import pytest
        return pytest.__version__


def pin_mismatch_message(required: str, installed: str) -> str:
    return (
        f"SIS tests require pytest {required}, the evaluator's pinned"
        f" runtime (EvaluationRuntimeProfile.pytest_version); this"
        f" interpreter has pytest {installed}, so every evaluator test"
        f" would fail with runtime_pin_mismatch. Install the pinned"
        f" version with `pip install -r requirements-lock.txt` or"
        f" `pip install -e .[dev]` and rerun. Set {ALLOW_UNPINNED_ENV}=1"
        f" to run under pytest {installed} anyway.")


def pytest_sessionstart(session):
    if os.environ.get(ALLOW_UNPINNED_ENV) == "1":
        return
    required = required_pytest_version()
    installed = installed_pytest_version()
    if installed != required:
        import pytest
        pytest.exit(pin_mismatch_message(required, installed),
                    returncode=PIN_MISMATCH_EXIT)


def pytest_ignore_collect(collection_path, config):
    if os.name == "nt" and os.path.realpath(os.fspath(collection_path)) == _V3:
        return True
    return None


def pytest_report_header(config):
    if os.name == "nt":
        return POSIX_ONLY_NOTE
    return None


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    # The header above is suppressed by -q (CI runs pytest -q); the
    # terminal summary is not.
    if os.name == "nt":
        terminalreporter.write_line(POSIX_ONLY_NOTE)
