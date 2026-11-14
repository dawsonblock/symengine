"""V336-01: memory trust derives from enforced controls, not a profile name.

The v3.3.5 audit reproduced this bypass: ``MemoryTrustProfile`` was a
plain dataclass, so a caller could build ``name="production"`` with every
trust requirement disabled. The store then constructed without signer
keys, a chain key, a witness or a verifier, and ``trust_status`` returned
``trusted`` for an unsigned legacy ``ExperienceRecordV1`` because it keyed
off the profile name alone.

These regressions pin the repaired contract: only recognized profile
modes exist, a production profile must enable every control, and a store
reports trust only while all of those controls are actually configured.
"""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sis.v3 import memory as memory_module
from sis.v3 import signatures
from sis.v3.contracts import ContractError, ExperienceRecordV1
from sis.v3.memory import (
    MemoryError,
    MemoryStore,
    MemoryTrustProfile,
    issue_experience_record,
)
from sis.v3.memory_witness import MemoryWitness

NOW = "2026-11-10T00:00:00Z"
CONTROLS = (
    "require_signed_records",
    "require_evaluator_evidence",
    "require_chain_signature",
    "require_witness",
    "require_registered_task",
)
PRODUCTION_REQUIRED = "production_profile_requires_every_trust_control"
DEVELOPMENT_FORBIDDEN = "development_profile_cannot_enable_trust_controls"


def _flags(value: bool) -> dict[str, bool]:
    return {control: value for control in CONTROLS}


def _production_profile(**overrides) -> MemoryTrustProfile:
    fields = _flags(True)
    fields.update(overrides)
    return MemoryTrustProfile(name="production", **fields)


def _v1_record(experience_id="exp-v1", episode_id="ep-v1"):
    return ExperienceRecordV1(
        schema_version=1,
        experience_id=experience_id,
        episode_id=episode_id,
        repository_registry_id="repo-a",
        task_fingerprint=hashlib.sha256(
            ("fp:" + episode_id).encode()).hexdigest(),
        task_category="convention-fix",
        agent_config_digest="a" * 64,
        trace_digest="b" * 64,
        outcome_receipt_digest="c" * 64,
        outcome="fail",
        failure_category="convention_unknown",
        lesson="unsigned legacy lesson",
        facts=("f",),
        hypotheses=("h",),
        applicability=({"kind": "language_is", "value": "python"},),
        counterexamples=(),
        provenance={"generator": "test", "method": "unit"},
        captured_at=NOW,
    )


class ProfileConstructionTests(unittest.TestCase):
    """Only recognized modes with a complete control set can exist."""

    def test_audit_bypass_profile_is_rejected(self):
        with self.assertRaisesRegex(ContractError, PRODUCTION_REQUIRED):
            MemoryTrustProfile(name="production", **_flags(False))

    def test_every_missing_production_control_is_rejected(self):
        for control in CONTROLS:
            with self.subTest(control=control):
                with self.assertRaisesRegex(ContractError, PRODUCTION_REQUIRED):
                    _production_profile(**{control: False})

    def test_production_equivalent_profile_is_accepted(self):
        profile = _production_profile()
        self.assertTrue(profile.production_trust)

    def test_development_profile_reports_no_production_trust(self):
        self.assertFalse(MemoryTrustProfile.development().production_trust)
        self.assertTrue(MemoryTrustProfile.production().production_trust)

    def test_development_profile_cannot_enable_controls(self):
        fields = _flags(False)
        fields["require_witness"] = True
        with self.assertRaisesRegex(ContractError, DEVELOPMENT_FORBIDDEN):
            MemoryTrustProfile(name="development", **fields)

    def test_unknown_profile_mode_is_rejected(self):
        with self.assertRaisesRegex(
                ContractError, "unknown_memory_trust_profile"):
            MemoryTrustProfile(name="prod", **_flags(True))

    def test_non_boolean_control_is_rejected(self):
        with self.assertRaisesRegex(
                ContractError, "memory_trust_profile_flags_must_be_boolean"):
            _production_profile(require_witness=1)

    def test_production_equivalent_profile_still_needs_store_controls(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(
                    ContractError, "production_requires_trusted_signer_keys"):
                MemoryStore(Path(temp) / "memory.db",
                            profile=_production_profile())

    def test_production_requires_registered_task_verifier(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _record_seed, record_public = signatures.generate_keypair()
            chain_seed, _chain_public = signatures.generate_keypair()
            witness_seed, _witness_public = signatures.generate_keypair()
            with self.assertRaisesRegex(
                    ContractError,
                    "production_requires_registered_task_verifier"):
                MemoryStore(
                    root / "db" / "memory.db",
                    trusted_signer_keys={
                        "exp-key-1": record_public.hex()},
                    chain_key=(chain_seed, "chain-key-1"),
                    profile=MemoryTrustProfile.production(),
                    witness=MemoryWitness(
                        root / "witness" / "w.jsonl",
                        seed=witness_seed, key_id="witness-key-1"),
                    verifier=object())


class TrustControlDerivationTests(unittest.TestCase):
    """A production store trusts only while its controls stay configured."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        record_seed, record_public = signatures.generate_keypair()
        chain_seed, _chain_public = signatures.generate_keypair()
        witness_seed, _witness_public = signatures.generate_keypair()
        self.store = MemoryStore(
            self.root / "db" / "memory.db",
            trusted_signer_keys={"exp-key-1": record_public.hex()},
            chain_key=(chain_seed, "chain-key-1"),
            profile=MemoryTrustProfile.production(),
            witness=MemoryWitness(
                self.root / "witness" / "w.jsonl",
                seed=witness_seed, key_id="witness-key-1"),
            verifier=SimpleNamespace(
                registered_task=lambda task_id: None))
        self.addCleanup(self.store.close)
        self.record = issue_experience_record(
            record_seed, "exp-key-1",
            experience_id="exp-1",
            episode_id="ep-1",
            repository_registry_id="repo-a",
            task_id="task-1",
            attempt_id="att-1",
            repo_snapshot_digest="a" * 64,
            task_fingerprint=hashlib.sha256(b"fp").hexdigest(),
            task_category="convention-fix",
            agent_config_digest="b" * 64,
            execution_receipt_digest="c" * 64,
            trace_digest="d" * 64,
            outcome_receipt_digest="e" * 64,
            outcome="fail",
            failure_category="convention_unknown",
            lesson="lesson",
            facts=("f",),
            hypotheses=("h",),
            applicability=({"kind": "language_is", "value": "python"},),
            counterexamples=(),
            provenance={"generator": "test", "method": "unit"},
            captured_at=NOW,
        )
        patcher = mock.patch.object(
            memory_module, "verify_experience_evidence", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store.ingest(self.record)

    def assert_untrusted(self, reason=None):
        status = self.store.trust_status(self.record)
        self.assertNotEqual(status, "trusted")
        if reason is not None:
            self.assertEqual(status, reason)

    def test_fully_configured_store_reports_trusted(self):
        self.assertEqual(self.store.trust_status(self.record), "trusted")

    def test_missing_signer_keys_never_trusted(self):
        self.store._signer_keys = None
        self.assert_untrusted("untrusted:trust_controls_not_configured")

    def test_missing_chain_key_never_trusted(self):
        self.store._chain_key = None
        self.assert_untrusted("untrusted:trust_controls_not_configured")

    def test_missing_witness_never_trusted(self):
        self.store._witness = None
        self.assert_untrusted("untrusted:trust_controls_not_configured")

    def test_missing_verifier_never_trusted(self):
        self.store._verifier = None
        self.assert_untrusted("untrusted:trust_controls_not_configured")

    def test_missing_control_fails_reads_closed(self):
        self.store._signer_keys = None
        with self.assertRaisesRegex(
                MemoryError, "trust_controls_not_configured"):
            self.store.get("exp-1")

    def test_production_store_rejects_unsigned_legacy_record(self):
        with self.assertRaisesRegex(MemoryError, "legacy_v1_record"):
            self.store.ingest(_v1_record())


class ForgedProfileTests(unittest.TestCase):
    """A renamed or flag-forged profile cannot manufacture trust."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = MemoryStore(
            Path(self.temp.name) / "memory.db",
            profile=MemoryTrustProfile.development())
        self.addCleanup(self.store.close)
        self.record = _v1_record()
        self.store.ingest(self.record)

    def test_renamed_development_profile_never_trusted(self):
        object.__setattr__(self.store._profile, "name", "production")
        self.assertEqual(
            self.store.trust_status(self.record),
            "untrusted:development_profile")

    def test_forged_control_flags_on_unconfigured_store_never_trusted(self):
        for control in CONTROLS:
            object.__setattr__(self.store._profile, control, True)
        object.__setattr__(self.store._profile, "name", "production")
        self.assertEqual(
            self.store.trust_status(self.record),
            "untrusted:trust_controls_not_configured")
