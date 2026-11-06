import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sis.errors import InvalidInput, RuleRejected, LLMError
from sis.expression import evaluate, validate_ast
from sis.induction import induce, generated_probes
from sis.model import CompatibleLLM
from sis.registry import Registry
from sis.service import Service
from sis.smt import bounded_disagreement

ROOT = Path(__file__).resolve().parents[1]


def fixture(name):
    return json.loads((ROOT / 'examples' / name).read_text('utf-8'))


class ExpressionTests(unittest.TestCase):
    def test_copy_first(self):
        self.assertEqual(evaluate({'op':'item', 'name':'s', 'index':0}, {'s':['Hello','Bye']}), 'Hello')

    def test_arithmetic_and_type(self):
        ast = {'op':'add','args':[{'op':'field','name':'a'}, {'op':'field','name':'b'}]}
        self.assertEqual(evaluate(ast, {'a':8,'b':-2}), 6)
        with self.assertRaises(InvalidInput):
            evaluate(ast, {'a':True,'b':2})

    def test_if_eq(self):
        a = {'op':'field','name':'x'}
        b = {'op':'field','name':'y'}
        ast = {'op':'if_eq','left':a,'right':b,'then':{'op':'const','value':'same'},'else':{'op':'const','value':'diff'}}
        self.assertEqual(evaluate(ast, {'x':'hi','y':'hi'}),'same')
        self.assertEqual(evaluate(ast, {'x':'hi','y':'no'}),'diff')

    def test_injection_rejected(self):
        for value in ({'op':'exec','code':'import os;os.system("rm -rf /")'},
                      {'op':'field','name':'__import__("os")'},
                      {'op':'const','value': {'$eval':'bad'}},
                      {'op':'add','args':[]},
                      {'op':'const','value':float('inf')}):
            with self.subTest(value=value), self.assertRaises(InvalidInput):
                validate_ast(value)

    def test_deep_rule_rejected(self):
        ast = {'op':'field','name':'a'}
        for _ in range(8): ast={'op':'neg','arg':ast}
        with self.assertRaises(InvalidInput): validate_ast(ast)

    def test_overflow_is_not_silent(self):
        ast={'op':'mul','args':[{'op':'field','name':'a'}, {'op':'field','name':'b'}]}
        with self.assertRaises(InvalidInput):
            evaluate(ast, {'a':1_000_000_000, 'b':1_000_000_000})


class InductionTests(unittest.TestCase):
    def test_additive_rule(self):
        req=fixture('arithmetic_study.json')
        result=induce(req['train'],req['validation'],namespace=req['namespace'])
        self.assertEqual(result['status'],'locally_validated')
        self.assertEqual(result['rule']['op'],'add')
        self.assertEqual(result['validation_passed'],3)

    def test_sequence_copy_rule(self):
        req=fixture('sequence_study.json')
        result=induce(req['train'],req['validation'],namespace=req['namespace'])
        self.assertEqual(result['status'],'locally_validated')
        self.assertEqual(result['rule'], {'op':'item','name':'sequence','index':0})

    def test_detect_ambiguity(self):
        req=fixture('ambiguous_study.json')
        result=induce(req['train'],req['validation'])
        self.assertEqual(result['status'],'ambiguous')
        self.assertIsNotNone(result['distinguishing_probe'])

    def test_no_holdout_stays_provisional(self):
        req=fixture('arithmetic_study.json')
        self.assertEqual(induce(req['train'])['status'],'provisional')

    def test_failed_validation_is_not_promotion_evidence(self):
        req=fixture('arithmetic_study.json')
        req['validation'][0]['output']=99
        result=induce(req['train'],req['validation'])
        self.assertEqual(result['status'],'validation_failed')

    def test_validation_overlap_rejected(self):
        req=fixture('arithmetic_study.json')
        with self.assertRaises(InvalidInput):
            induce(req['train'], [req['train'][0], req['validation'][0]])

    def test_duplicate_train_inputs_rejected(self):
        req=fixture('arithmetic_study.json')
        with self.assertRaises(InvalidInput):
            induce(req['train']+[req['train'][0]],req['validation'])

    def test_schema_mismatch_rejected(self):
        req=fixture('arithmetic_study.json')
        req['validation'][0]['inputs']['b']='5'
        with self.assertRaises(InvalidInput):
            induce(req['train'],req['validation'])

    def test_large_num_fails_closed(self):
        req=fixture('arithmetic_study.json')
        req['train'][0]['inputs']['a']=10**200
        with self.assertRaises(InvalidInput):
            induce(req['train'],req['validation'])

    def test_synthetic_probes_not_grounds(self):
        samples=list(generated_probes({'a':1,'b':2}))
        self.assertTrue(any(p['a']!=p['b'] for p in samples))
        self.assertLessEqual(len(samples),256)

    def test_search_budget_is_explicit(self):
        req=fixture('arithmetic_study.json')
        result=induce(req['train'],req['validation'],max_candidates=100)
        self.assertEqual(result['status'],'search_incomplete')
        self.assertTrue(result['search_truncated'])


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory()
        self.db=str(Path(self.dir.name)/'study.sqlite3')
        self.service=Service(self.db)

    def tearDown(self):
        self.service.registry.close()
        self.dir.cleanup()

    def train(self):
        return self.service.study(fixture('arithmetic_study.json'))

    def test_persistence_and_prediction(self):
        result=self.train()
        self.assertEqual(result['promotion']['status'],'active')
        ans=self.service.predict({'namespace':'arithmetic_demo','inputs':{'a':17,'b':-2}})
        self.assertEqual(ans['output'],15)
        self.assertEqual(ans['status'],'predicted')
        self.assertTrue(self.service.registry.verify_audit()['valid'])
        self.assertEqual(len(Registry(self.db).list_rules('arithmetic_demo')),1)

    def test_unvalidated_promotion_rejected(self):
        result=induce(fixture('arithmetic_study.json')['train'])
        with self.assertRaises(RuleRejected):
            self.service.registry.promote(result)

    def test_duplicate_promotion_is_idempotent(self):
        a=self.train()
        b=self.train()
        self.assertTrue(a['promotion']['created'])
        self.assertFalse(b['promotion']['created'])
        self.assertEqual(self.service.registry.verify_audit()['events_verified'],1)

    def test_feedback_mismatch_suspends(self):
        out=self.train()
        rule=out['promotion']['id']
        feedback=self.service.feedback({'namespace':'arithmetic_demo','rule_id':rule,
                                       'inputs':{'a':4,'b':6},'observed_output':100})
        self.assertFalse(feedback['matched'])
        self.assertEqual(feedback['evidence_origin'],'user_reported')
        self.assertEqual(self.service.predict({'namespace':'arithmetic_demo','inputs':{'a':5,'b':8}})['status'],'abstain')
        self.assertEqual(self.service.registry.verify_audit()['events_verified'],2)

    def test_audit_mutation_detected(self):
        self.train()
        self.service.registry.conn.execute("UPDATE audit SET event_json=? WHERE seq=1", ('{"fake":true}',))
        self.service.registry.conn.commit()
        self.assertFalse(self.service.registry.verify_audit()['valid'])

    def test_namespace_isolation(self):
        self.train()
        pred=self.service.predict({'namespace':'another','inputs':{'a':5,'b':6}})
        self.assertEqual(pred['status'],'abstain')

    def test_study_does_not_accept_client_supplied_rule(self):
        req=fixture('ambiguous_study.json')
        req['rule']={'op':'const','value':'fake'}
        req['status']='locally_validated'
        result=self.service.study(req)
        self.assertNotEqual(result['status'],'locally_validated')

    def test_llm_off_by_default(self):
        req=fixture('arithmetic_study.json')
        req['use_llm']=True
        with self.assertRaises(InvalidInput): self.service.study(req)

    def test_chat_without_prediction_abstains_and_does_not_call_llm(self):
        self.service.enable_llm=True
        with patch('sis.service.CompatibleLLM') as mocked:
            ans=self.service.chat({'namespace':'unknown','inputs':{'a':1},'question':'hey'})
        mocked.assert_not_called()
        self.assertEqual(ans['status'],'abstain')


class ModelTests(unittest.TestCase):
    def test_insecure_http_remote_rejected(self):
        with self.assertRaises(LLMError):
            CompatibleLLM(base_url='http://example.com/v1/chat/completions',model='test')

    def test_local_and_https_allowed(self):
        self.assertEqual(CompatibleLLM(base_url='http://localhost:1234/v1/chat/completions',model='local').model,'local')
        self.assertEqual(CompatibleLLM(base_url='https://example.com/v1/chat/completions',model='remote').model,'remote')

    def test_no_valid_z3_if_not_installed(self):
        try:
            import z3
        except ImportError:
            req=fixture('arithmetic_study.json')
            with self.assertRaises(InvalidInput):
                induce(req['train'],req['validation'],use_z3=True)


if __name__ == '__main__': unittest.main()
