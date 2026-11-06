"""SIS3-101/102: fresh-extraction release verification + SQLite lifecycle."""
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))
import build_release  # noqa: E402
import verify_release  # noqa: E402


def _copy_subset(dst: Path, files: dict[str, bytes]):
    for rel, data in files.items():
        path = dst / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _copy_subset(self.root, {
            "src/pkg/a.py": b"print(1)\n",
            "src/pkg/b.py": b"X = 2\n",
            "docs/readme.md": b"hi\n",
        })

    def _build(self):
        files = build_release.inventory(self.root)
        (self.root / "RELEASE_SHA256.json").write_text(
            json.dumps({"schema": 1, "files": files}, sort_keys=True)
        )

    def test_fresh_tree_verifies(self):
        self._build()
        self.assertEqual(verify_release.verify_tree(self.root)["files"], 3)

    def test_tampered_file_fails_closed(self):
        self._build()
        (self.root / "src/pkg/a.py").write_bytes(b"print('pwned')\n")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_release.verify_tree(self.root)

    def test_extra_file_fails_closed(self):
        self._build()
        (self.root / "src/pkg/evil.py").write_bytes(b"import os\n")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            verify_release.verify_tree(self.root)

    def test_missing_file_fails_closed(self):
        self._build()
        (self.root / "src/pkg/b.py").unlink()
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            verify_release.verify_tree(self.root)

    def test_missing_manifest_fails(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            verify_release.verify_tree(self.root)

    def test_manifest_cannot_cover_itself(self):
        files = build_release.inventory(self.root)
        self.assertNotIn("RELEASE_SHA256.json", files)
        self.assertNotIn("SOURCE_SHA256.json", files)

    def test_skips_cache_and_db(self):
        _copy_subset(self.root, {
            "src/__pycache__/a.pyc": b"x",
            "data/state.db": b"x",
            "junk.log": b"x",
        })
        files = build_release.inventory(self.root)
        self.assertEqual(len(files), 3)


class SqliteLifecycleTests(unittest.TestCase):
    """Every SQLite owner supports close() and context management."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_registry_close_and_cm(self):
        from sis.registry import Registry
        reg = Registry(str(self.root / "r.db"))
        reg.close()
        with Registry(str(self.root / "r2.db")) as reg2:
            self.assertIs(reg2, reg2.__enter__())

    def test_family_eval_close_and_cm(self):
        from sis.family_eval import FamilyExperimentVault
        v = FamilyExperimentVault(str(self.root / "f.db"))
        v.close()
        with FamilyExperimentVault(str(self.root / "f2.db")):
            pass

    def test_skill_holdout_close_and_cm(self):
        from sis.skill_holdout import SkillHoldoutVault
        key = b"k" * 32
        v = SkillHoldoutVault(str(self.root / "s.db"), key=key)
        v.close()
        with SkillHoldoutVault(str(self.root / "s2.db"), key=key):
            pass

    def test_evaluator_vault_close_and_cm(self):
        from sis.sealed_eval import EvaluatorVault
        key = b"k" * 32
        v = EvaluatorVault(str(self.root / "e.db"), key=key)
        v.close()
        with EvaluatorVault(str(self.root / "e2.db"), key=key):
            pass

    def test_closed_connection_raises_on_use(self):
        import sqlite3
        from sis.family_eval import FamilyExperimentVault
        v = FamilyExperimentVault(str(self.root / "f3.db"))
        v.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            v.con.execute("SELECT 1")


class CanonicalArchiveBindingTests(unittest.TestCase):
    """The release archive must not embed release/ and must match its source."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "proj"
        _copy_subset(self.root, {
            "src/pkg/a.py": b"print(1)\n",
            "docs/readme.md": b"hi\n",
            "release/notes.json": b'{"old": true}\n',
            "release/SIS-old.zip": b"PK-not-really-a-zip",
        })
        self.target = self.base / "out" / "SIS.zip"

    def _build(self):
        import build_canonical_zip
        return build_canonical_zip.build(self.root, self.target, require_clean=False)

    def test_release_dir_is_never_archived(self):
        report = self._build()
        self.assertEqual(report["source_files"], 2)
        self.assertEqual(report["source_binding"]["files"], 2)
        with zipfile.ZipFile(self.target) as z:
            names = z.namelist()
        self.assertFalse([n for n in names if "/release/" in n])
        self.assertFalse([n for n in names if n.endswith(".zip")])
        manifest = json.loads((self.root / "RELEASE_SHA256.json").read_text())
        self.assertFalse([r for r in manifest["files"] if r.startswith("release/")])

    def test_archive_uses_explicit_project_dir(self):
        import build_canonical_zip
        report = build_canonical_zip.build(
            self.root, self.target, require_clean=False,
            project="SIS-v9.9.9-TEST")
        self.assertEqual(report["project"], "SIS-v9.9.9-TEST")
        with zipfile.ZipFile(self.target) as z:
            self.assertTrue(all(
                name.startswith("SIS-v9.9.9-TEST/")
                for name in z.namelist()))

    def test_archive_rejects_unsafe_project_dir(self):
        import build_canonical_zip
        with self.assertRaisesRegex(ValueError, "safe path component"):
            build_canonical_zip.build(
                self.root, self.target, require_clean=False,
                project="../escape")

    def test_archive_is_bound_to_source_tree(self):
        self._build()
        import verify_release
        self.assertTrue(verify_release.verify_against_tree(self.target, self.root)["source_bound"])

    def test_stale_archive_fails_source_binding(self):
        self._build()
        (self.root / "src/pkg/a.py").write_bytes(b"print('changed')\n")
        import verify_release
        with self.assertRaisesRegex(ValueError, "source binding hash mismatch"):
            verify_release.verify_against_tree(self.target, self.root)

    def test_verify_rejects_embedded_provenance(self):
        import verify_release
        manifest = {"schema": 1, "files": {"release/old.zip": "0" * 64}}
        self.target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(self.target, "w") as z:
            z.writestr("proj/RELEASE_SHA256.json", json.dumps(manifest))
            z.writestr("proj/release/old.zip", b"PK")
        with self.assertRaisesRegex(ValueError, "out-of-band"):
            verify_release.verify(self.target)

    def test_build_refuses_dirty_source(self):
        import subprocess
        import build_canonical_zip
        repo = self.root
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@e",
                        "commit", "-qm", "init"], check=True)
        (repo / "src/pkg/a.py").write_bytes(b"print(2)\n")
        with self.assertRaisesRegex(ValueError, "uncommitted changes"):
            build_canonical_zip.build(repo, self.target)


class FreshExtractionGateTests(unittest.TestCase):
    """The release build must fail closed on a broken extracted archive."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _tree(self, *, source=b"VALUE = 1\n",
              test_body=b"def test_ok():\n    assert True\n"):
        _copy_subset(self.root, {
            "src/pkg/a.py": source,
            "tests/v3/test_candidates.py": test_body,
        })
        return self.root

    def test_passing_extraction_is_recorded(self):
        import package_release
        report = package_release.fresh_extraction_checks(self._tree())
        self.assertTrue(report["compileall_src"])
        self.assertEqual(
            report["extracted_test_smoke"]["returncode"], 0)
        self.assertEqual(
            report["extracted_test_smoke"]["command"],
            "pytest -q tests/v3/test_candidates.py")

    def test_failing_smoke_fails_the_build(self):
        import package_release
        tree = self._tree(
            test_body=b"def test_bad():\n    assert False\n")
        with self.assertRaisesRegex(ValueError, "smoke test failed"):
            package_release.fresh_extraction_checks(tree)

    def test_missing_smoke_test_fails_the_build(self):
        import package_release
        tree = self._tree()
        (tree / "tests/v3/test_candidates.py").unlink()
        with self.assertRaisesRegex(ValueError, "smoke test failed"):
            package_release.fresh_extraction_checks(tree)

    def test_uncompilable_source_fails_the_build(self):
        import package_release
        tree = self._tree(source=b"def broken(:\n")
        with self.assertRaisesRegex(ValueError, "compile check failed"):
            package_release.fresh_extraction_checks(tree)


if __name__ == "__main__":
    unittest.main()
