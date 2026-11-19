# Evidence corrections

## 2026-11-13 — `E_vs_A` contrast in the five-arm reports

`analyze_report()` in `src/sis/v3/learning_qualification.py` built
`learning_qualification.contrasts["E_vs_A"]` with `treatment="A"`, so the
entry compared baseline A with itself. The code fix is commit `cd918e3`.

The two historical report files were corrected post hoc by replacing only
that derived field with the independently computed
`learning_qualification.decisive_contrast` from the same file:

| File | Original entry | Corrected entry |
| --- | --- | --- |
| `five_arm_demo.json` | A vs A, delta 0.0 | E 2/2 vs A 0/2, delta 1.0, p=0.5 |
| `real_agent_five_arm.json` | A vs A, delta 0.0 | E 4/8 vs A 4/8, delta 0.0, p=1.0 |

No per-task outcomes, paired win/loss counts, governed metrics, or
decisive contrasts were changed. The corrected field now equals the
file's `decisive_contrast`. These remain historical records; the
correction is limited to the derived contrast that the generator
mislabeled.
