"""Every entrypoint that registers private tests names its custody mode.

The verifier refuses private material under an unspecified custody mode,
but a tool can still silence that by constructing a permissive verifier.
This scan keeps the opt-out visible in the source: a ``register_task``
call with ``files=`` must name ``custody=``, and a constant
``custody="shared"`` must sit beside an explicit
``allow_shared_custody=True``.
"""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCANNED = ("tools", "scripts")


def _private_registrations(path):
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (func.attr if isinstance(func, ast.Attribute)
                else getattr(func, "id", ""))
        if name != "register_task":
            continue
        keywords = {keyword.arg for keyword in node.keywords if keyword.arg}
        if "files" not in keywords:
            continue
        yield node, keywords, source


class PrivateRegistrationCustodyTests(unittest.TestCase):
    def test_private_registrations_name_their_custody(self):
        missing = []
        for base in SCANNED:
            for path in sorted((ROOT / base).rglob("*.py")):
                for node, keywords, _source in _private_registrations(path):
                    if "custody" not in keywords:
                        missing.append(
                            f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(
            missing, [],
            "private registrations must name custody explicitly")

    def test_a_shared_registration_has_an_explicit_verifier_opt_out(self):
        missing = []
        for base in SCANNED:
            for path in sorted((ROOT / base).rglob("*.py")):
                for node, _keywords, source in _private_registrations(path):
                    shared = any(
                        keyword.arg == "custody"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value == "shared"
                        for keyword in node.keywords)
                    if shared and "allow_shared_custody=True" not in source:
                        missing.append(
                            f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(
            missing, [],
            "shared custody requires allow_shared_custody=True in the tool")


if __name__ == "__main__":
    unittest.main()
