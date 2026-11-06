"""Live-campaign tool wiring (v3.3 M9): deterministic dry-run.

The real campaign invokes ``codex exec``; this test swaps in a scripted
agent with the same keyword convention as the deterministic campaign to
exercise the full lifecycle — episodes, induction, optimizer, holdout
arms, qualification, serving, revocation — without any API calls.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))

import governed_campaign as gc  # noqa: E402
import governed_live_campaign as glc  # noqa: E402

# Schema-faithful adapter: (module, keyword, good_source) per task name.
GOOD = {
    "money": ("money.py", "decimal",
              "from decimal import Decimal, ROUND_HALF_UP\n"
              "def round_money(x):\n"
              "    return str(Decimal(str(x)).quantize("
              "Decimal('0.01'), rounding=ROUND_HALF_UP))\n"),
    "slug": ("slug.py", "non-alphanumeric",
             "import re\ndef slugify(s):\n"
             "    return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')\n"),
    "money2": ("pricing.py", "decimal",
               "from decimal import Decimal, ROUND_HALF_UP\n"
               "def format_price(x):\n"
               "    return str(Decimal(str(x)).quantize("
               "Decimal('0.01'), rounding=ROUND_HALF_UP))\n"),
    "slug2": ("permalink.py", "non-alphanumeric",
              "import re\ndef permalink(title):\n"
              "    return re.sub(r'[^a-z0-9]+', '-', title.lower())"
              ".strip('-')\n"),
}


def _scripted(ctx, *, tasks):
    name = ctx.task.task_id.split("-", 1)[1]
    mod, keyword, good = GOOD[name]
    text = " ".join(ctx.guidance.helpful_next_checks) \
        if ctx.guidance is not None else ""
    if keyword.lower() in text.lower():
        (ctx.workspace / mod).write_text(good)
    return {"tokens_used": 120, "tools_used": 3}


class LiveCampaignWiringTests(unittest.TestCase):
    def test_full_lifecycle_dry_run(self):
        original = glc.codex_agent
        glc.codex_agent = _scripted
        try:
            with tempfile.TemporaryDirectory() as temp:
                argv = sys.argv
                sys.argv = ["governed_live_campaign.py",
                            "-o", temp, "--wall", "60"]
                try:
                    rc = glc.main()
                finally:
                    sys.argv = argv
                self.assertEqual(rc, 0)
                evidence = json.loads(
                    (Path(temp) / "live_campaign_evidence.json").read_text())
                self.assertEqual(evidence["kind"], "governed_live_campaign")
                counts = evidence["evaluation"]["solved_counts"]
                self.assertGreater(counts["E"], counts["A"])
                self.assertTrue(evidence["registry"]["qualified"])
                self.assertIsNotNone(evidence["served_after_revocation"])
                post = evidence["served_after_revocation"]
                self.assertTrue(all(
                    "round_money" not in s for s in post["checks"]))
        finally:
            glc.codex_agent = original


if __name__ == "__main__":
    unittest.main()
