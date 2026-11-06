# SIS v3.3.2 efficacy status (M9)

Status: **NOT DEMONSTRATED. No improvement claim is made.**

## What the plan requires

M9 compares unguided Codex against memory-only, skills-only,
symbolic-only and combined SIS configurations on preregistered,
repository-disjoint tasks, and reports verified solve rate, negative
transfer, latency and cost with uncertainty estimates.

## What was executed

The v3.3.1 attempt ran an eight-task real five-arm Codex campaign. The
external Codex quota blocked four tasks. The gate is recorded as
`BLOCKED_EXTERNAL_AGENT_QUOTA`, not as a task failure. The scripted
five-arm demonstration remains labelled a demonstration and cannot
satisfy a production qualification.

## What is missing

- A preregistered, repository-disjoint task set large enough for the
  declared protocol (the v3.3.1 certificate protocol requires 29 tasks;
  the eight-task attempt cannot satisfy it).
- A complete real-agent run with all five arms and no quota block.
- Verified solve-rate, negative-transfer, latency and cost estimates
  with uncertainty intervals.

## Consequence

The release manifest status remains
`IMPLEMENTED_NOT_EFFICACY_QUALIFIED`. The authority-consistency work in
M0–M5 does not change the efficacy claim. Do not describe SIS v3.3.2 as
improving agent performance until a valid M9 run is executed and
reported.
