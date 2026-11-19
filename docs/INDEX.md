# Documentation index

SIS keeps two kinds of documents: the **current operational set**, which
describes the code and release as they are, and the **historical record**,
which explains how the current state was reached and is not a current
claim. Start with the first section; use the last one for provenance.

## Start here

| Document | Contents |
| --- | --- |
| [../README.md](../README.md) | What SIS is, install, quick start |
| [v3/STATUS.md](v3/STATUS.md) | Implementation status, gate by gate |
| [v3/ARCHITECTURE_V3_3.md](v3/ARCHITECTURE_V3_3.md) | v3 subsystem design |
| [v3/QUALIFICATION_REPORT_V3_3_8.md](v3/QUALIFICATION_REPORT_V3_3_8.md) | Current release: what is implemented and what is not qualified |
| [../CHANGELOG.md](../CHANGELOG.md) | Release-by-release history |
| [../UPGRADE_README.md](../UPGRADE_README.md) | Operator-facing upgrade notes |

## Operations, security and release

| Document | Contents |
| --- | --- |
| [v3/RELEASE_PROCESS.md](v3/RELEASE_PROCESS.md) | Branches, tags, seal ritual, verification commands |
| [v3/OPERATIONS.md](v3/OPERATIONS.md) | Running and recovering the service |
| [V332_OPERATIONS.md](V332_OPERATIONS.md) | Deployment, recovery, key rotation |
| [v3/SECURITY_BOUNDARIES_V3_3.md](v3/SECURITY_BOUNDARIES_V3_3.md) | v3 trust boundaries |
| [v3/TRUST_BOUNDARIES.md](v3/TRUST_BOUNDARIES.md) | What each component trusts |
| [v3/THREAT_MODEL.md](v3/THREAT_MODEL.md) | v3 adversaries and mitigations |
| [SECURITY.md](SECURITY.md) | Security policy |
| [SECURITY_THREAT_MODEL.md](SECURITY_THREAT_MODEL.md) | Cross-version threat model |
| [EXECUTION_IDENTITY.md](EXECUTION_IDENTITY.md) | Worker and execution identity |
| [AUTHORITY_CHECKPOINTS.md](AUTHORITY_CHECKPOINTS.md) | Authority checkpoints |
| [EVIDENCE_CUSTODY.md](EVIDENCE_CUSTODY.md) | Revocation and dependency tracking |
| [EVALUATION_CERTIFICATES.md](EVALUATION_CERTIFICATES.md) | Signed qualification evidence |

## Verification and evidence

| Document | Contents |
| --- | --- |
| [v3/SANDBOX_QUALIFICATION_GATE2.md](v3/SANDBOX_QUALIFICATION_GATE2.md) | Live Docker containment probe and signed isolation attestation |
| [v3/TEST_MATRIX.md](v3/TEST_MATRIX.md) | Test suites and what each covers |
| [v3/EVIDENCE_PROTOCOL.md](v3/EVIDENCE_PROTOCOL.md) | Evidence records and contracts |
| [v3/EVALUATION_PROTOCOL_V3_3.md](v3/EVALUATION_PROTOCOL_V3_3.md) | v3 evaluation protocol |
| [v3/WORKER_VALIDATION_PLAN.md](v3/WORKER_VALIDATION_PLAN.md) | Worker validation plan |
| [EVALUATION.md](EVALUATION.md) | Evaluation framework |
| [EVALUATION_PROTOCOL.md](EVALUATION_PROTOCOL.md) | Cross-version evaluation protocol |
| [EVALUATOR_V1_4.md](EVALUATOR_V1_4.md) | Evaluator v1.4 |
| [audits/BASELINE_INTEGRITY.md](audits/BASELINE_INTEGRITY.md) | Baseline integrity audit |
| [v3/episodes/live-001/README.md](v3/episodes/live-001/README.md) | Live episode 001 evidence |
| [v3/episodes/live-002/README.md](v3/episodes/live-002/README.md) | Live episode 002 evidence |

## Design and learning

| Document | Contents |
| --- | --- |
| [v3/MEMORY_DESIGN.md](v3/MEMORY_DESIGN.md) | Verified memory design |
| [v3/EVOLUTION_DESIGN.md](v3/EVOLUTION_DESIGN.md) | Skill evolution design |
| [v3/SKILL_INGESTION.md](v3/SKILL_INGESTION.md) | v3 skill ingestion |
| [v3/SKILL_HOLDOUTS.md](v3/SKILL_HOLDOUTS.md) | Skill holdout evaluation |
| [v3/CODEX_ADAPTER.md](v3/CODEX_ADAPTER.md) | Codex adapter |
| [v3/IMPLEMENTATION_REPORT_V3_3.md](v3/IMPLEMENTATION_REPORT_V3_3.md) | v3.3 implementation report |
| [v3/MIGRATION.md](v3/MIGRATION.md) | v3 migration guide |
| [SKILL_INGESTION.md](SKILL_INGESTION.md) | Cross-version skill ingestion |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Pre-v3 architecture |
| [V331_ARCHITECTURE.md](V331_ARCHITECTURE.md) | v3.3.1 architecture |

## Historical record

Dated reports that explain how the current state was reached. They are
not current claims; the operational documents above supersede them where
they disagree.

| Document | Contents |
| --- | --- |
| [v3/G1_GATE_REPORT.md](v3/G1_GATE_REPORT.md), [G2](v3/G2_GATE_REPORT.md), [G3](v3/G3_GATE_REPORT.md), [G4](v3/G4_GATE_REPORT.md) | v3.1-alpha engineering gates |
| [v3/QUALIFICATION_REPORT.md](v3/QUALIFICATION_REPORT.md), [V3_3_0](v3/QUALIFICATION_REPORT_V3_3_0.md), [V3_3_4](v3/QUALIFICATION_REPORT_V3_3_4.md), [V3_3_5](v3/QUALIFICATION_REPORT_V3_3_5.md), [V3_3_6](v3/QUALIFICATION_REPORT_V3_3_6.md), [V3_3_7](v3/QUALIFICATION_REPORT_V3_3_7.md) | Earlier release qualifications |
| [v3/V2_BASELINE.md](v3/V2_BASELINE.md) | v2 baseline |
| [v3/V32_GAP_MAP.md](v3/V32_GAP_MAP.md) | v3.2 gap map |
| [v3/V33_LIMITATIONS.md](v3/V33_LIMITATIONS.md) | v3.3 limitations |
| [v3/RELEASE_NOTES_V3_3.md](v3/RELEASE_NOTES_V3_3.md) | v3.3 release notes |
| [v3/UPGRADE_2026_10_24.md](v3/UPGRADE_2026_10_24.md) | 2026-10-24 upgrade |
| [V1_5_TRANSFER_AND_QUALIFICATION.md](V1_5_TRANSFER_AND_QUALIFICATION.md), [V1_6](V1_6_PAIRED_LLM_BENCHMARK.md), [V1_7](V1_7_PROCEDURAL_SKILLS.md), [V1_8](V1_8_PROCEDURAL_HOLDOUT_AND_DISTILLATION.md), [V1_9](V1_9_LORA_AND_NEURAL_COMPARISON.md), [V2_0](V2_0_FAMILY_QUALIFICATION.md), [V2_1](V2_1_TYPED_TRACE_LEARNING.md), [V2_2](V2_2_EXPERIENCE_ABSTRACTION.md), [V2_3](V2_3_WORKFLOW_LEARNING.md), [V2_4](V2_4_CODE_REPAIR.md) | v1.5–v2.4 milestone reports |
| [TEST_REPORT_V1_2.md](TEST_REPORT_V1_2.md) … [TEST_REPORT_V2_4.md](TEST_REPORT_V2_4.md) | Per-version test reports |
| [UPGRADE_V1_1.md](UPGRADE_V1_1.md), [V1_2](UPGRADE_V1_2.md), [V1_3](UPGRADE_V1_3.md) | Early upgrade notes |
| [MIGRATION_V330_TO_V331.md](MIGRATION_V330_TO_V331.md) | v3.3.0 → v3.3.1 migration |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | Earlier release notes |
| [ROADMAP.md](ROADMAP.md) | Roadmap at the time of writing |
| [LIMITATIONS.md](LIMITATIONS.md) | Earlier limitations |
| [LEGACY_README.md](LEGACY_README.md) | Pre-3.3.3 README |
| [../UPGRADE_RELEASE_NOTES_2026-10-24.md](../UPGRADE_RELEASE_NOTES_2026-10-24.md) | 2026-10-24 upgrade notes |
| [../AUTHORITY_RECOVERY_RELEASE_NOTES.md](../AUTHORITY_RECOVERY_RELEASE_NOTES.md) | Authority recovery notes |

## Release artifacts

| Document | Contents |
| --- | --- |
| [../release/README.md](../release/README.md) | Sealed archive, digest, provenance status |
| [../release/release_manifest.json](../release/release_manifest.json) | Archive identity and source commit |
| [../release/verification.json](../release/verification.json) | Fresh-extraction verification |
