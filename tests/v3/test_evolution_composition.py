"""Skill evolution + guidance composition (v3.3 M4/M5)."""
import tempfile
import unittest
from pathlib import Path

from sis.v3.candidates import CandidateRegistry
from sis.v3.composition import compose_guidance
from sis.v3.contracts import ContractError, ProcedureRecordV1
from sis.v3.evolution import (DevEvalResult, EvolutionBudget, Frontier,
                              FrontierEntry, SkillOptimizer, append_step,
                              drop_step, fitness, reorder_step,
                              specialize_step)
from tests.v3.test_candidates import make_candidate


def _res(solved=1, tasks=2, regressions=0, tokens=100):
    return DevEvalResult(tasks=tasks, solved=solved,
                         regressions=regressions, tokens=tokens,
                         tool_calls=1, wall_seconds=1)


class _Eval:
    """Dev evaluator: scores by keyword coverage; never sees holdouts."""

    def __init__(self, keyword):
        self.keyword = keyword
        self.calls = 0

    def evaluate(self, candidate, dev_tasks):
        self.calls += 1
        text = " ".join(candidate.payload.get("steps", ())).lower()
        hit = 1 if self.keyword in text else 0
        return DevEvalResult(tasks=2, solved=hit, regressions=0,
                             tokens=100, tool_calls=1, wall_seconds=1)


class MutatorTests(unittest.TestCase):
    def test_mutators_are_pure_payload_transforms(self):
        base = {"title": "s", "steps": ["a", "b"]}
        self.assertEqual(append_step("c")(base)["steps"], ["a", "b", "c"])
        self.assertEqual(drop_step(0)(base)["steps"], ["b"])
        self.assertEqual(reorder_step(0, 1)(base)["steps"], ["b", "a"])
        self.assertEqual(specialize_step(0, " x")(base)["steps"],
                         ["a x", "b"])
        self.assertIsNone(drop_step(5)(base))
        self.assertIsNone(append_step("a")(base))  # no duplicate steps


class OptimizerTests(unittest.TestCase):
    def test_bounded_search_finds_keyword_variant(self):
        ev = _Eval("decimal")
        opt = SkillOptimizer(
            evaluator=ev,
            mutators=(append_step("Use decimal rounding."),),
            budget=EvolutionBudget(max_iterations=2, max_evaluations=8,
                                   frontier_size=2))
        entries = opt.optimize(
            [{"title": "s", "steps": ["generic"]}], ["dev-task"],
            target_task_family="fam",
            repository_scope={"kind": "family_id", "value": "fam-a"})
        self.assertTrue(entries)
        self.assertGreater(entries[0].fitness, 0)
        self.assertLessEqual(ev.calls, 8)

    def test_budget_caps_are_enforced(self):
        ev = _Eval("anything")
        opt = SkillOptimizer(
            evaluator=ev,
            mutators=tuple(append_step(f"step-{i}") for i in range(10)),
            budget=EvolutionBudget(max_iterations=10, max_evaluations=3,
                                   max_candidates=50))
        opt.optimize([{"title": "s", "steps": ["x"]}], ["t"],
                     target_task_family="f",
                     repository_scope={"kind": "global", "value": ""})
        self.assertLessEqual(ev.calls, 3)

    def test_candidates_land_at_proposed_only(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reg = CandidateRegistry(Path(tmp.name) / "c.db")
        self.addCleanup(reg.close)
        opt = SkillOptimizer(
            evaluator=_Eval("k"),
            mutators=(append_step("k"),),
            budget=EvolutionBudget(max_iterations=1, max_evaluations=4),
            registry_submit=lambda c: reg.submit(c, actor_role="learner"))
        opt.optimize([{"title": "s", "steps": ["x"]}], ["t"],
                     target_task_family="f",
                     repository_scope={"kind": "global", "value": ""})
        # optimizer output is intake-only: nothing self-qualifies
        self.assertEqual(reg.by_state("qualified"), [])
        self.assertTrue(reg.by_state("proposed"))

    def test_frontier_tiebreak_is_content_not_wallclock(self):
        # Equal-fitness entries must rank by content_digest, not by
        # candidate.digest (which covers created_at and varies with time).
        from sis.v3.contracts import CandidateV1
        def _cand(steps, at, cid):
            d = make_candidate(cid=cid, payload={"steps": steps}).to_dict()
            d["created_at"] = at
            return CandidateV1.from_dict(d)
        early = _cand(["aaa"], "2026-10-24T00:00:00Z", "e")
        late = _cand(["zzz"], "2026-10-25T00:00:00Z", "l")
        frontier = Frontier(2)
        frontier.insert(FrontierEntry(late, 1.0))
        frontier.insert(FrontierEntry(early, 1.0))
        expected = min(early, late, key=lambda c: c.content_digest)
        self.assertIs(frontier.best().candidate, expected)

    def test_fitness_penalizes_regressions(self):
        good = fitness(_res(solved=2, tasks=2))
        bad = fitness(_res(solved=0, tasks=2, regressions=2))
        self.assertGreater(good, 0)
        self.assertLess(bad, 0)

    def test_per_child_failures_are_isolated_and_recorded(self):
        class _Flaky:
            def evaluate(self, candidate, dev_tasks):
                if "boom" in " ".join(candidate.payload.get("steps", ())):
                    raise RuntimeError("evaluator exploded")
                return _res()

        opt = SkillOptimizer(
            evaluator=_Flaky(),
            mutators=(append_step("boom"), append_step("safe")),
            budget=EvolutionBudget(max_iterations=1, max_evaluations=8))
        entries = opt.optimize(
            [{"title": "s", "steps": ["x"]}], ["t"],
            target_task_family="f",
            repository_scope={"kind": "global", "value": ""})
        # the exploding child neither aborts the run nor enters frontier
        self.assertEqual(len(entries), 1)
        self.assertEqual(len(opt.failures), 1)
        self.assertEqual(opt.failures[0]["stage"], "evaluate")

        # a failing registry submit is likewise recorded, not fatal
        def bad_submit(_c):
            raise RuntimeError("registry down")
        opt2 = SkillOptimizer(
            evaluator=_Eval("safe"), mutators=(append_step("safe"),),
            budget=EvolutionBudget(max_iterations=1, max_evaluations=4),
            registry_submit=bad_submit)
        opt2.optimize([{"title": "s", "steps": ["x"]}], ["t"],
                      target_task_family="f",
                      repository_scope={"kind": "global", "value": ""})
        self.assertEqual(opt2.failures[0]["stage"], "submit")


class CompositionTests(unittest.TestCase):
    def proc(self, steps, pid="p1"):
        return ProcedureRecordV1(
            schema_version=1, procedure_id=pid, revision=1,
            intent="i", language="python", frameworks=(),
            task_signatures=(), failure_signatures=(), preconditions=(),
            contraindications=(), steps=tuple(steps),
            required_verification=("t",), counterexample_refs=(),
            evidence_refs=("1" * 64,),
            outcome_distribution={"tasks": 1, "successes": 1,
                                  "failures": 0, "regressions": 0},
            status="qualified", expires_at=None)

    def test_precedence_dedup_and_budget(self):
        proc = self.proc(["Use decimal."])
        skill = make_candidate(payload={"steps": ["Use decimal.",
                                                  "Also dedup."]})
        out = compose_guidance([skill, proc])
        self.assertFalse(out.abstained)
        self.assertEqual(out.steps, ("Use decimal.", "Also dedup."))
        tiny = compose_guidance([skill], token_budget=1)
        self.assertTrue(tiny.abstained)

    def test_conflict_precedence_and_abstain_policies(self):
        hi = make_candidate(cid="hi", ctype="symbolic_procedure",
                            payload={"steps": ["Always use decimal."]})
        lo = make_candidate(cid="lo", ctype="prompt_variant",
                            payload={"steps": ["Never use decimal."]})
        out = compose_guidance([hi, lo], conflict_policy="precedence")
        self.assertEqual(out.steps, ("Always use decimal.",))
        self.assertTrue(out.resolutions)
        abst = compose_guidance([hi, lo], conflict_policy="abstain")
        self.assertTrue(abst.abstained)
        self.assertEqual(abst.reason, "conflicting_evidence")

    def test_empty_input_abstains(self):
        self.assertTrue(compose_guidance([]).abstained)


if __name__ == "__main__":
    unittest.main()
