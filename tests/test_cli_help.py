"""`sis --help` lists every command once, grouped by area; commands are unchanged."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sis import cli

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _commands(parser: argparse.ArgumentParser) -> dict:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    raise AssertionError("sis has no subcommands")


class CommandGroupTests(unittest.TestCase):
    def setUp(self):
        self.parser = cli.build_parser()
        self.commands = _commands(self.parser)

    def test_every_command_is_in_exactly_one_group(self):
        grouped = [name for _, names in cli.COMMAND_GROUPS for name in names]
        self.assertEqual(len(grouped), len(set(grouped)), "a command is listed twice")
        self.assertEqual(set(grouped), set(self.commands),
                         "COMMAND_GROUPS and the registered commands differ")

    def test_help_lists_each_command_once_under_its_group(self):
        text = self.parser.format_help()
        self.assertNotIn("{train,", text)
        for title, names in cli.COMMAND_GROUPS:
            self.assertIn(title + ":", text)
            section = text.split(title + ":", 1)[1].split("\n\n", 1)[0]
            for name in names:
                with self.subTest(command=name):
                    self.assertRegex(section, rf"(?m)^  {name}\s")
        for name in self.commands:
            self.assertEqual(len([line for line in text.splitlines()
                                  if line.split() and line.split()[0] == name]), 1, name)
        self.assertNotIn("Other:", text)

    def test_unknown_command_is_still_refused(self):
        with contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            self.parser.parse_args(["no-such-command"])
        self.assertIn("invalid choice", err.getvalue())


class CommandBehaviourTests(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def test_core_commands_run_as_before(self):
        with tempfile.TemporaryDirectory() as temp:
            db = str(Path(temp) / "k.sqlite3")
            code, out = self.run_cli("--db", db, "train",
                                     str(EXAMPLES / "arithmetic_study.json"))
            self.assertIn(code, (0, None))
            self.assertEqual(json.loads(out)["status"], "locally_validated")
            code, out = self.run_cli("--db", db, "predict",
                                     str(EXAMPLES / "predict.json"))
            self.assertEqual(json.loads(out)["output"], 11)
            code, out = self.run_cli("--db", db, "skill-study",
                                     str(EXAMPLES / "skill_sum_study.json"))
            self.assertEqual(json.loads(out)["status"], "locally_validated")
            code, out = self.run_cli("--db", db, "audit")
            self.assertTrue(json.loads(out)["valid"])


if __name__ == "__main__":
    unittest.main()
