"""The evaluator image installs a fully pinned, hashed dependency set."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "docker" / "sandbox" / "Dockerfile"
LOCK = ROOT / "docker" / "sandbox" / "requirements.lock"


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


if __name__ == "__main__":
    unittest.main()
