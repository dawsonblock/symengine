"""v1.3 attack-oriented regression tests for event replay and conflicting induction."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sis.errors import InvalidInput, RuleRejected
from sis.service import Service
from sis.validation import canonical
from sis.registry import Registry

ROOT = Path(__file__).resolve().parents[1]


def example():
    return json.loads((ROOT / 'examples' / 'arithmetic_study.json').read_text())


class StrictTypeTests(unittest.TestCase):
    def test_bool_and_int_outputs_are_not_equivalent(self):
        from sis.induction import _matches
        ast={'op':'const','value':True}
        examples=[{'inputs':{'a':i},'output':1} for i in range(3)]
        self.assertFalse(_matches(ast, examples))

    def test_malformed_audit_event_fails_closed(self):
        s=Service(':memory:')
        try:
            s.registry.conn.execute("INSERT INTO audit(seq,event_json,previous_hash,event_hash) VALUES(1,'[]',?,?)",
                                    ('0'*64, hashlib.sha256(('0'*64+'\n[]').encode()).hexdigest()))
            s.registry.conn.commit()
            self.assertEqual(s.registry.verify_audit()['reason'],'invalid_audit_event')
        finally:
            s.registry.close()


class SemanticReplayTests(unittest.TestCase):
    def setUp(self):
        self.s = Service(':memory:')
        self.rid = self.s.study(example())['promotion']['id']
        self.conn = self.s.registry.conn

    def tearDown(self):
        self.s.registry.close()

    def test_positive_feedback_with_semantic_audit(self):
        self.s.feedback({'namespace':'arithmetic_demo', 'rule_id':self.rid,
                         'inputs':{'a':1, 'b':2}, 'observed_output':3})
        self.assertTrue(self.s.registry.verify_audit()['valid'])

    def test_rewritten_chain_cannot_skip_positive_counter(self):
        self.s.feedback({'namespace':'arithmetic_demo', 'rule_id':self.rid,
                         'inputs':{'a':1, 'b':2}, 'observed_output':3})
        seq, body, prev, head = self.conn.execute(
            'SELECT seq,event_json,previous_hash,event_hash FROM audit WHERE seq=2').fetchone()
        forged = json.loads(body)
        forged['projection']['feedback_positive'] = 2  # forged double-credit
        rewritten = canonical(forged)
        forged_hash = hashlib.sha256((prev + '\n' + rewritten).encode('utf8')).hexdigest()
        self.conn.execute('UPDATE audit SET event_json=?,event_hash=? WHERE seq=2',
                          (rewritten,forged_hash))
        self.conn.execute('UPDATE rules SET feedback_positive=2 WHERE id=?',(self.rid,))
        self.conn.commit()
        # Hashes and final projection agree; semantic transition must still reject.
        self.assertEqual(self.s.registry.verify_audit()['reason'],'invalid_rule_transition')
        self.assertEqual(self.s.predict({'namespace':'arithmetic_demo','inputs':{'a':2,'b':3}})['status'],'abstain')
        with self.assertRaises(RuleRejected):
            self.s.list_rules('arithmetic_demo')

    def test_transition_cannot_resurrect_suspended_rule(self):
        self.s.feedback({'namespace':'arithmetic_demo','rule_id':self.rid,
                         'inputs':{'a':2,'b':4},'observed_output':99})
        self.assertTrue(self.s.registry.verify_audit()['valid'])
        self.s.feedback({'namespace':'arithmetic_demo','rule_id':self.rid,
                         'inputs':{'a':2,'b':4},'observed_output':6})
        self.assertTrue(self.s.registry.verify_audit()['valid'])
        self.assertEqual(self.s.list_rules('arithmetic_demo'),[])

    def test_invalid_feedback_type_does_not_suspend(self):
        with self.assertRaises(InvalidInput):
            self.s.feedback({'namespace':'arithmetic_demo','rule_id':self.rid,
                             'inputs':{'a':2,'b':4},'observed_output':True})
        self.assertTrue(self.s.registry.verify_audit()['valid'])
        self.assertEqual(self.s.registry.verify_audit()['events_verified'],1)


class AdmissionFirewallTests(unittest.TestCase):
    def setUp(self):
        self.s = Service(':memory:')
        self.original = example()
        self.rid = self.s.study(self.original)['promotion']['id']

    def tearDown(self):
        self.s.registry.close()

    def test_conflicting_rule_rejected_without_mutating_registry(self):
        other = example()
        for ex in other['train'] + other['validation']:
            ex['output'] = ex['inputs']['a'] - ex['inputs']['b']
        with self.assertRaisesRegex(RuleRejected,'active rule conflict'):
            self.s.study(other)
        self.assertEqual(self.s.registry.verify_audit()['events_verified'],1)
        self.assertEqual(self.s.list_rules('arithmetic_demo')[0]['id'],self.rid)
        self.assertEqual(self.s.predict({'namespace':'arithmetic_demo','inputs':{'a':7,'b':8}})['output'],15)

    def test_retired_rule_no_longer_blocks_admission(self):
        self.s.retire({'namespace':'arithmetic_demo','rule_id':self.rid})
        other=example()
        for ex in other['train']+other['validation']:
            ex['output']=ex['inputs']['a']-ex['inputs']['b']
        r=self.s.study(other)
        self.assertEqual(r['promotion']['status'],'active')
        self.assertEqual(self.s.predict({'namespace':'arithmetic_demo','inputs':{'a':7,'b':8}})['output'],-1)

    def test_idempotent_promotion_of_same_rule(self):
        again=self.s.study(example())
        self.assertFalse(again['promotion']['created'])
        self.assertEqual(self.s.registry.verify_audit()['events_verified'],1)


if __name__ == '__main__':
    unittest.main()
