"""Golden canonical schema examples: parse, digest-stable, round-trip."""
import unittest
from pathlib import Path

from sis.v3.contracts import (
    ExecutionReceiptV1,
    GuidanceRequestV1,
    GuidanceV1,
    ObservationEventV1,
    OutcomeReceiptV1,
    PatchProposalV1,
    ProcedureRecordV1,
    PromotionDecisionV1,
    TaskEnvelopeV1,
    canonical_json,
)

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "src" / "sis" / "v3" / "schemas"
EXPECTED = {
    "task_envelope_v1.json": TaskEnvelopeV1,
    "observation_event_v1.json": ObservationEventV1,
    "patch_proposal_v1.json": PatchProposalV1,
    "execution_receipt_v1.json": ExecutionReceiptV1,
    "outcome_receipt_v1.json": OutcomeReceiptV1,
    "procedure_record_v1.json": ProcedureRecordV1,
    "promotion_decision_v1.json": PromotionDecisionV1,
    "guidance_request_v1.json": GuidanceRequestV1,
    "guidance_v1.json": GuidanceV1,
}


class GoldenSchemaTests(unittest.TestCase):
    def test_all_expected_files_present(self):
        for name in EXPECTED:
            self.assertTrue((SCHEMA_DIR / name).is_file(), name)

    def test_each_parses_and_roundtrips(self):
        for name, cls in EXPECTED.items():
            raw = (SCHEMA_DIR / name).read_bytes()
            record = cls.from_json(raw)
            self.assertEqual(record.canonical_bytes(), raw.rstrip(b"\n"))

    def test_digests_are_stable(self):
        digests = {
            name: cls.from_json((SCHEMA_DIR / name).read_bytes()).digest
            for name, cls in EXPECTED.items()
        }
        self.assertEqual(len(set(digests.values())), len(EXPECTED))
        # Re-deriving must be identical (canonical bytes, not float formatting).
        again = {
            name: cls.from_json((SCHEMA_DIR / name).read_bytes()).digest
            for name, cls in EXPECTED.items()
        }
        self.assertEqual(digests, again)


if __name__ == "__main__":
    unittest.main()
