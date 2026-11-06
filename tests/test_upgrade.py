"""v1.1 regression, adversarial and model-independent integration tests."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sis.active import suggest_queries
from sis.evaluation import benchmark
from sis.errors import InvalidInput, RuleRejected
from sis.expression import evaluate
from sis.service import Service
from sis.tooling import definitions

ROOT = Path(__file__).resolve().parents[1]


def fixture(filename):
    return json.loads((ROOT/'examples'/filename).read_text(encoding='utf8'))


class ActiveQueryTests(unittest.TestCase):
    def test_can_identify_informative_question(self):
        req = fixture('ambiguous_study.json')
        result = suggest_queries(req['train'])
        self.assertEqual(result['status'], 'oracle_queries')
        self.assertTrue(result['queries'])
        self.assertTrue(result['queries'][0]['oracle_label_required'])
        self.assertGreater(len(result['queries'][0]['candidate_outputs']), 1)
        self.assertNotIn('output', result['queries'][0])
        self.assertNotIn('observed_output', result['queries'][0])
        self.assertNotIn(result['queries'][0]['inputs'], [e['inputs'] for e in req['train']])

    def test_deterministic(self):
        req = fixture('ambiguous_study.json')
        self.assertEqual(suggest_queries(req['train']), suggest_queries(req['train']))

    def test_bounded_outputs(self):
        req = fixture('ambiguous_study.json')
        result = suggest_queries(req['train'], max_candidates=100, max_hypotheses=2, max_probes=2, limit=1)
        self.assertLessEqual(len(result['queries']), 1)
        self.assertLessEqual(result['hypotheses_sampled'], 2)

    def test_duplicate_train_rejected(self):
        req = fixture('ambiguous_study.json')
        req['train'].append(req['train'][0])
        with self.assertRaises(InvalidInput):
            suggest_queries(req['train'])

    def test_invalid_limits(self):
        req = fixture('ambiguous_study.json')
        for args in ({'limit':0},{'max_probes':999},{'max_hypotheses':1},{'max_candidates':False}):
            with self.subTest(args=args), self.assertRaises(InvalidInput):
                suggest_queries(req['train'], **args)

    def test_query_does_not_use_validation(self):
        req = fixture('ambiguous_study.json')
        a = suggest_queries(req['train'])
        req['validation'][0]['output'] = -999
        b = suggest_queries(req['train'])
        self.assertEqual(a,b)


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture('arithmetic_study.json')
        self.case['test'] = [
            {'inputs':{'a':30,'b':12},'output':42},
            {'inputs':{'a':-7,'b':5},'output':-2},
            {'inputs':{'a':-31,'b':-11},'output':-42},
        ]

    def test_arithmetic_generalizes_on_local_fixture(self):
        r=benchmark(self.case)
        self.assertEqual(r['status'],'evaluated')
        self.assertEqual(r['test_correct'],3)
        self.assertEqual(r['coverage'],1.0)
        self.assertEqual(r['overall_accuracy'],1.0)
        self.assertFalse(r['promoted'])
        self.assertIn('caller-supplied',r['source'])

    def test_cross_split_duplicate_fails(self):
        self.case['test'][1]['inputs'] = self.case['train'][0]['inputs']
        with self.assertRaises(InvalidInput):
            benchmark(self.case)

    def test_validation_test_overlap_fails(self):
        self.case['test'][1]['inputs'] = self.case['validation'][0]['inputs']
        with self.assertRaises(InvalidInput):
            benchmark(self.case)

    def test_schema_mismatch_fails(self):
        self.case['test'][0]['inputs']['b'] = 'text'
        with self.assertRaises(InvalidInput):
            benchmark(self.case)

    def test_test_outcome_does_not_change_rule_selection(self):
        a = benchmark(self.case)
        self.case['test'][0]['output']=900
        b = benchmark(self.case)
        self.assertEqual(a['rule_digest'],b['rule_digest'])
        self.assertEqual(b['test_correct'],2)

    def test_benchmark_does_not_persist(self):
        with tempfile.TemporaryDirectory() as d:
            service = Service(str(Path(d)/'registry.db'))
            try:
                r=service.benchmark(self.case)
                self.assertEqual(r['status'],'evaluated')
                self.assertEqual(service.list_rules('arithmetic_demo'),[])
                self.assertTrue(service.registry.verify_audit()['valid'])
            finally:
                service.registry.close()


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.s = Service(str(Path(self.d.name)/'rules.db'))
        r=self.s.study(fixture('arithmetic_study.json'))
        self.rid=r['promotion']['id']

    def tearDown(self):
        self.s.registry.close()
        self.d.cleanup()

    def test_projection_verified(self):
        r=self.s.registry.verify_audit()
        self.assertTrue(r['valid'])
        self.assertEqual(r['rules_verified'],1)
        self.assertEqual(r['events_verified'],1)

    def test_projection_tamper_fails_closed(self):
        c=self.s.registry.conn
        c.execute('UPDATE rules SET expression_json=? WHERE id=?', ('{"op":"const","value":777}',self.rid))
        c.commit()
        self.assertEqual(self.s.registry.verify_audit()['reason'],'rule_projection_mismatch')
        self.assertEqual(self.s.predict({'namespace':'arithmetic_demo','inputs':{'a':1,'b':2}})['status'],'abstain')
        with self.assertRaises(RuleRejected):
            self.s.registry.retire('arithmetic_demo',self.rid)

    def test_mutated_counter_detected(self):
        c=self.s.registry.conn
        c.execute('UPDATE rules SET feedback_positive=999 WHERE id=?',(self.rid,))
        c.commit()
        self.assertFalse(self.s.registry.verify_audit()['valid'])

    def test_untracked_rule_rejected(self):
        c=self.s.registry.conn
        c.execute('UPDATE rules SET id=? WHERE id=?',('abcd',self.rid))
        c.commit()
        self.assertEqual(self.s.registry.verify_audit()['reason'],'unaccounted_rule_or_missing_projection')

    def test_missing_audit_event_rejected(self):
        c=self.s.registry.conn
        c.execute('DELETE FROM audit')
        c.commit()
        self.assertFalse(self.s.registry.verify_audit()['valid'])

    def test_positive_feedback_produces_new_projection(self):
        feedback=self.s.feedback({'namespace':'arithmetic_demo','rule_id':self.rid,
                                  'inputs':{'a':2,'b':4},'observed_output':6})
        self.assertTrue(feedback['matched'])
        self.assertEqual(self.s.registry.verify_audit()['events_verified'],2)
        self.assertEqual(self.s.registry.verify_audit()['rules_verified'],1)

    def test_negative_feedback_suspends_and_verifies(self):
        feedback=self.s.feedback({'namespace':'arithmetic_demo','rule_id':self.rid,
                                  'inputs':{'a':2,'b':4},'observed_output':999})
        self.assertFalse(feedback['matched'])
        self.assertTrue(self.s.registry.verify_audit()['valid'])
        self.assertEqual(self.s.predict({'namespace':'arithmetic_demo','inputs':{'a':10,'b':10}})['status'],'abstain')

    def test_retirement_is_irreversible(self):
        self.assertTrue(self.s.retire({'namespace':'arithmetic_demo','rule_id':self.rid})['changed'])
        self.assertFalse(self.s.retire({'namespace':'arithmetic_demo','rule_id':self.rid})['changed'])
        self.assertEqual(self.s.registry.verify_audit()['events_verified'],2)
        self.assertEqual(self.s.predict({'namespace':'arithmetic_demo','inputs':{'a':2,'b':5}})['status'],'abstain')
        with self.assertRaises(RuleRejected):
            self.s.feedback({'namespace':'arithmetic_demo','rule_id':self.rid,
                             'inputs':{'a':2,'b':5},'observed_output':7})

    def test_legacy_event_without_projection_fails_closed(self):
        c=self.s.registry.conn
        body=json.dumps({'event':'rule_promoted','rule_id':self.rid},separators=(',',':'),sort_keys=True)
        import hashlib
        hashval=hashlib.sha256(('0'*64+'\n'+body).encode()).hexdigest()
        c.execute('UPDATE audit SET event_json=?, event_hash=? WHERE seq=1',(body,hashval))
        c.commit()
        self.assertEqual(self.s.registry.verify_audit()['reason'],'legacy_or_missing_rule_projection')


class ToolingTests(unittest.TestCase):
    def test_tools_are_valid_json(self):
        r=definitions()
        self.assertEqual({t['function']['name'] for t in r},{'sis_predict','sis_suggest_queries','sis_transfer','sis_skill_predict','sis_workflow_predict','sis_code_preview'})
        self.assertEqual(json.loads(json.dumps(r)),r)

    def test_tool_definitions_copy(self):
        r=definitions()
        r[0]['function']['name']='corrupt'
        self.assertEqual(definitions()[0]['function']['name'],'sis_predict')

    def test_service_can_query_without_llm(self):
        with tempfile.TemporaryDirectory() as d:
            s=Service(str(Path(d)/'r.db'))
            try:
                with patch('sis.service.CompatibleLLM') as llm:
                    result=s.query({'train':fixture('ambiguous_study.json')['train']})
                llm.assert_not_called()
                self.assertEqual(result['status'],'oracle_queries')
            finally:
                s.registry.close()

if __name__=='__main__':
    unittest.main()

class BridgeTests(unittest.TestCase):
    def test_readonly_bridge_rejects_mutation_commands(self):
        from sis.bridge import ToolBridge
        with tempfile.TemporaryDirectory() as d:
            s=Service(str(Path(d)/'r.db'))
            try:
                bridge=ToolBridge(s)
                for command in ('sis_retire','sis_promote','sis_study','__import__'):
                    with self.subTest(command=command), self.assertRaises(InvalidInput):
                        bridge.invoke(command, {})
            finally:
                s.registry.close()

    def test_readonly_bridge_handles_json(self):
        from sis.bridge import ToolBridge
        s=Service(':memory:')
        try:
            result=ToolBridge(s).invoke('sis_predict','{"inputs":{"a":1}}')
            self.assertEqual(result['status'],'abstain')
        finally:
            s.registry.close()

    def test_reject_oversized_invalid_arguments(self):
        from sis.bridge import ToolBridge
        s=Service(':memory:')
        try:
            bridge=ToolBridge(s)
            with self.assertRaises(InvalidInput):
                bridge.invoke('sis_predict','x'*128001)
            with self.assertRaises(InvalidInput):
                bridge.invoke('sis_predict','{')
            with self.assertRaises(InvalidInput):
                bridge.invoke('sis_predict',{'inputs':{'a':1},'promote':True})
        finally:
            s.registry.close()
