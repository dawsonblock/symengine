"""The evaluator images install fully pinned, hashed dependency sets."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "docker" / "sandbox" / "Dockerfile"
LOCK = ROOT / "docker" / "sandbox" / "requirements.lock"
TESTDEPS_DOCKERFILE = ROOT / "docker" / "sandbox" / "Dockerfile.testdeps"
TESTDEPS_LOCK = ROOT / "docker" / "sandbox" / "requirements-testdeps.lock"
_HASHED = re.compile(
    r"^([A-Za-z0-9_.-]+)==[^ ]+( --hash=sha256:[0-9a-f]{64})+$")


def _requirements(path: Path) -> list[str]:
    return [line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")]


def _instructions(path: Path, keyword: str) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith(keyword + " ")]


class EvaluatorImageLockTests(unittest.TestCase):
    def test_the_image_installs_the_lock_with_hashes(self):
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("requirements.lock", dockerfile)
        self.assertIn("--require-hashes", dockerfile)

    def test_every_locked_requirement_is_pinned_and_hashed(self):
        lines = [
            line.strip() for line in LOCK.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(
                line, r"^[A-Za-z0-9_.-]+==[^ ]+ --hash=sha256:[0-9a-f]{64}$",
                line)

    def test_the_supported_runner_is_locked(self):
        lock = LOCK.read_text(encoding="utf-8")
        self.assertRegex(lock, r"(?m)^pytest==8\.4\.2 --hash=sha256:")


class TestDependencyVariantTests(unittest.TestCase):
    """sis-evaluator:3.3.9-testdeps: the base image plus hashed test libs."""

    def test_the_variant_keeps_the_base_image_user_and_layout(self):
        for keyword in ("FROM", "USER", "WORKDIR", "ENV"):
            with self.subTest(keyword=keyword):
                self.assertEqual(
                    _instructions(TESTDEPS_DOCKERFILE, keyword),
                    _instructions(DOCKERFILE, keyword))
        self.assertRegex(_instructions(DOCKERFILE, "FROM")[0],
                         r"@sha256:[0-9a-f]{64}$")

    def test_the_variant_installs_both_locks_with_hashes(self):
        dockerfile = TESTDEPS_DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("--require-hashes", dockerfile)
        self.assertIn("--only-binary=:all:", dockerfile)
        self.assertIn("-r /tmp/requirements.lock", dockerfile)
        self.assertIn("-r /tmp/requirements-testdeps.lock", dockerfile)

    def test_no_committed_dockerfile_references_a_build_proxy(self):
        for path in (DOCKERFILE, TESTDEPS_DOCKERFILE):
            text = path.read_text(encoding="utf-8").lower()
            with self.subTest(path=path.name):
                for needle in ("proxy", "pip_cert", ".crt", "ca-bundle"):
                    self.assertNotIn(needle, text)

    def test_every_variant_requirement_is_pinned_and_hashed(self):
        lines = _requirements(TESTDEPS_LOCK)
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line, _HASHED, line)

    def test_the_variant_adds_the_common_test_libraries_only(self):
        def names(path):
            return {_HASHED.match(line).group(1).lower()
                    for line in _requirements(path)}
        added = names(TESTDEPS_LOCK)
        self.assertLessEqual(
            {"hypothesis", "pytest-mock", "pytest-timeout", "freezegun",
             "pyyaml", "toml"}, added)
        # nose does not import on Python 3.12; the runner set is not
        # re-pinned here, so the variant cannot diverge from the base.
        self.assertNotIn("nose", added)
        self.assertFalse(added & names(LOCK))


if __name__ == "__main__":
    unittest.main()
