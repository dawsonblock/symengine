"""v1.5 unit and integration tests: local fixtures, NOT independent holdouts."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sis.errors import InvalidInput, RuleRejected
from sis.expression import evaluate
from sis.service import Service
from sis.sealed_eval import EvaluatorVault
from sis.qualification import DEFAULT_POLICY, assess, check_policy, wilson_lower
from sis.transfer import map_expression
from sis.validation import digest

KEY = b'local_only_qualification_evaluator_secret_2026_unique'


def arithmetic_study():
    def ex(x,y): return {'inputs':{'a':x,'b':y},'output':x+y}
    return {'namespace':'arith','train':[ex(1,4),ex(2,7),ex(-3,5),ex(5,-2),ex(0,8)],
            'validation':[ex(4,9),ex(-4,-6),ex(11,3)], 'promote':True}


def eval_dataset():
    ex=lambda x:{'inputs':{'x':x},'output':x+2}
    return {'namespace':'testqual', 'task_id':'qual_40x40',
            'train':[ex(x) for x in (-6,-2,0,3,5)],
            'validation':[ex(x) for x in (7,9,13)],
            'test':[ex(x) for x in range(100,140)],
            'shifted_test':[ex(x) for x in range(-250,-210)]}


class TestTransfer(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.service=Service(Path(self.tmp.name)/'rules.sqlite3')
        self.promoted=self.service.study(arithmetic_study())
        self.assertEqual(self.promoted['promotion']['status'],'active')
        self.rid=self.promoted['promotion']['id']
        self.template={'source_namespace':'arith','rule_id':self.rid,'field_map':{'a':'left','b':'right'},
                       'inputs':{'left':12,'right':-2}}

    def tearDown(self):
        self.service.registry.close()
        self.tmp.cleanup()

    def test_correct_transfer(self):
        result=self.service.transfer(self.template)
        self.assertEqual(result['status'],'predicted')
        self.assertEqual(result['output'],10)
        self.assertEqual(result['qualification'],'unvalidated_target_hypothesis')

    def test_no_registry_writes(self):
        before=self.service.registry.verify_audit()
        self.service.transfer(self.template)
        self.assertEqual(self.service.registry.verify_audit(),before)

    def test_mapped_ast_validated(self):
        rule=self.service.registry.list_rules('arith')[0]
        mapped=map_expression(rule['rule'],rule['schema'],self.template['inputs'],self.template['field_map'])
        self.assertEqual(evaluate(mapped,{'left':12,'right':-2}),10)
        self.assertEqual(digest(mapped),self.service.transfer(self.template)['transfer_digest'])

    def test_partial_mapping_rejected(self):
        request=copy.deepcopy(self.template)
        request['field_map']={'a':'left'}
        with self.assertRaises(InvalidInput): self.service.transfer(request)

    def test_alias_mapping_rejected(self):
        request=copy.deepcopy(self.template)
        request['field_map']={'a':'left','b':'left'}
        with self.assertRaises(InvalidInput): self.service.transfer(request)

    def test_unexpected_target_field_rejected(self):
        request=copy.deepcopy(self.template)
        request['inputs']['third']=33
        with self.assertRaises(InvalidInput): self.service.transfer(request)

    def test_type_mismatch_rejected(self):
        request=copy.deepcopy(self.template)
        request['inputs']['left']=True
        with self.assertRaises(InvalidInput): self.service.transfer(request)

    def test_mapping_identifier_rejected(self):
        request=copy.deepcopy(self.template)
        request['field_map']['a']='oops.bad'
        with self.assertRaises(InvalidInput): self.service.transfer(request)

    def test_no_auto_field_name_guessing(self):
        request=copy.deepcopy(self.template)
        del request['field_map']
        with self.assertRaises(InvalidInput): self.service.transfer(request)

    def test_no_retired_rule_transfer(self):
        self.service.retire({'namespace':'arith','rule_id':self.rid})
        with self.assertRaises(InvalidInput): self.service.transfer(self.template)

    def test_no_tampered_audit_transfer(self):
        self.service.registry.conn.execute('UPDATE rules SET status=? WHERE id=?',('suspended',self.rid))
        self.service.registry.conn.commit()
        with self.assertRaises(RuleRejected): self.service.transfer(self.template)

    def test_batch_transfer(self):
        inp={'source_namespace':'arith','rule_id':self.rid,'field_map':self.template['field_map'],
             'inputs':[{'left':x,'right':1} for x in range(12)]}
        res=self.service.transfer_batch(inp)
        self.assertEqual(res['count'],12)
        self.assertEqual(res['predicted'],12)
        self.assertEqual([r['output'] for r in res['results']],list(range(1,13)))

    def test_batch_atomic_validation(self):
        inp={'source_namespace':'arith','rule_id':self.rid,'field_map':self.template['field_map'],
             'inputs':[self.template['inputs'],{'left':True,'right':2}]}
        with self.assertRaises(InvalidInput): self.service.transfer_batch(inp)

    def test_batch_overflow(self):
        inp={'source_namespace':'arith','rule_id':self.rid,'field_map':self.template['field_map'],
             'inputs':[self.template['inputs']]*65}
        with self.assertRaises(InvalidInput): self.service.transfer_batch(inp)

    def test_list_field_mapping(self):
        expr={'op':'item','name':'seq','index':1}
        mapped=map_expression(expr,{'seq':['int','str']},{'values':[7,'hi']},{'seq':'values'})
        self.assertEqual(evaluate(mapped,{'values':[7,'hi']}),'hi')
        with self.assertRaises(InvalidInput):
            map_expression(expr,{'seq':['int','str']},{'values':['hi',7]},{'seq':'values'})


class TestQualification(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.vault=EvaluatorVault(Path(self.tmp.name)/'vault.db',key=KEY)

    def tearDown(self):
        self.vault.close()
        self.tmp.cleanup()

    def score(self,dataset=None):
        public=self.vault.seal(dataset or eval_dataset())
        proposal=EvaluatorVault.make_submission(public)
        self.assertEqual(proposal['status'],'candidate')
        receipt=self.vault.score(public,proposal['submission'])
        return public, receipt

    def test_precommitted_default_threshold(self):
        public,receipt=self.score()
        self.assertEqual(public['qualification_policy'],check_policy(DEFAULT_POLICY))
        self.assertIn('qualification_policy',public)
        self.assertEqual(receipt['metrics']['test']['correct'],40)
        q=self.vault.qualify(public,receipt)
        self.assertEqual(q['assessment']['status'],'policy_pass')
        self.assertTrue(self.vault.verify_qualification(public,receipt,q)['valid'])

    def test_small_sample_fails_gate(self):
        d=eval_dataset(); d['test']=d['test'][:3]; d['shifted_test']=d['shifted_test'][:3]
        pub,receipt=self.score(d)
        q=self.vault.qualify(pub,receipt)
        self.assertEqual(q['assessment']['status'],'unqualified')
        self.assertIn('test_too_small',q['assessment']['reasons'])
        self.assertIn('shifted_test_too_small',q['assessment']['reasons'])

    def test_missing_shift_gate(self):
        d=eval_dataset(); d.pop('shifted_test')
        public,receipt=self.score(d)
        q=self.vault.qualify(public,receipt)
        self.assertEqual(q['assessment']['status'],'unqualified')
        self.assertIn('required_test_domains_missing',q['assessment']['reasons'])

    def test_custom_policy_committed(self):
        d=eval_dataset(); d['qualification_policy']={**DEFAULT_POLICY,'min_overall_accuracy':0.99}
        public,receipt=self.score(d)
        q=self.vault.qualify(public,receipt)
        self.assertEqual(q['assessment']['policy']['min_overall_accuracy'],0.99)
        self.assertEqual(q['assessment']['status'],'policy_pass')

    def test_policy_change_after_seal_rejected(self):
        public,receipt=self.score()
        public['qualification_policy']['min_coverage']=0.5
        with self.assertRaises(RuleRejected): self.vault.qualify(public,receipt)

    def test_tampered_receipt_rejected(self):
        public,receipt=self.score()
        receipt['metrics']['test']['correct']=0
        with self.assertRaises(RuleRejected): self.vault.qualify(public,receipt)

    def test_tampered_qualification_rejected(self):
        public,receipt=self.score()
        q=self.vault.qualify(public,receipt)
        q['assessment']['status']='unqualified'
        with self.assertRaises(RuleRejected): self.vault.verify_qualification(public,receipt,q)

    def test_qualification_replay_fails_different_evaluator_key(self):
        public,receipt=self.score()
        q=self.vault.qualify(public,receipt)
        with EvaluatorVault(Path(self.tmp.name)/'vault.db',key=b'x'*32) as other:
            with self.assertRaises(RuleRejected): other.verify_qualification(public,receipt,q)

    def test_underpowered_wilson(self):
        self.assertLess(wilson_lower(3,3),0.5)
        self.assertGreater(wilson_lower(40,40),0.85)
        self.assertEqual(wilson_lower(0,0),0.0)
        with self.assertRaises(InvalidInput): wilson_lower(True,10)

    def test_nan_bool_and_weak_policy_rejected(self):
        for override in ({'min_coverage':float('nan')}, {'min_test':True}, {'min_test':2},
                         {'min_wilson_lower':0.3}, {'min_baseline_gain':float('inf')}):
            with self.subTest(override=override):
                with self.assertRaises(InvalidInput): check_policy({**DEFAULT_POLICY,**override})

    def test_low_accuracy_despite_perfect_coverage(self):
        # Separately check policy scoring; this pure function MUST be used only after vault.verify.
        public={'evaluation_id':'x', 'qualification_policy':check_policy(DEFAULT_POLICY)}
        poor={'rule_digest':'id','metrics':{'test':{'count':40,'answered':40,'correct':20,
                         'train_majority_baseline_accuracy':0.25},
                  'shifted_test':{'count':40,'answered':40,'correct':20,
                         'train_majority_baseline_accuracy':0.25}}}
        q=assess(public,poor)
        self.assertEqual(q['status'],'unqualified')
        self.assertIn('test_accuracy_below_threshold',q['reasons'])

    def test_old_public_cannot_retroactively_qualify(self):
        q=assess({'evaluation_id':'old'}, {'metrics':{}})
        self.assertEqual(q['status'],'unqualified')
        self.assertIn('policy_not_precommitted',q['reasons'])

    def test_vault_reopen_verification(self):
        public,receipt=self.score()
        qualification=self.vault.qualify(public,receipt)
        self.vault.close()
        self.vault=EvaluatorVault(Path(self.tmp.name)/'vault.db',key=KEY)
        self.assertTrue(self.vault.verify_qualification(public,receipt,qualification)['valid'])

    def test_qualification_does_not_mutate_record(self):
        public,receipt=self.score()
        stored=self.vault.conn.execute('SELECT receipt_json, used FROM tasks WHERE evaluation_id=?',
                                       (public['evaluation_id'],)).fetchone()
        self.vault.qualify(public,receipt)
        self.assertEqual(stored,self.vault.conn.execute('SELECT receipt_json,used FROM tasks WHERE evaluation_id=?',
                             (public['evaluation_id'],)).fetchone())


class TestCLI(unittest.TestCase):
    def test_cli_transfer_and_eval_qualify(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t); root=Path(__file__).resolve().parents[1]
            env={**os.environ,'PYTHONPATH':str(root/'src'),'SIS_EVAL_HMAC_KEY':KEY.decode()}
            study=base/'study.json'; study.write_text(json.dumps(arithmetic_study()))
            db=base/'db.sqlite3'
            def run(*args):
                return subprocess.run([sys.executable,'-m','sis','--db',str(db),*args],
                                      cwd=base, env=env, capture_output=True,text=True)
            p=run('train',str(study));self.assertEqual(p.returncode,0,p.stderr)
            rid=json.loads(p.stdout)['promotion']['id']
            transfer=base/'transfer.json'
            transfer.write_text(json.dumps({'source_namespace':'arith','rule_id':rid,
                                             'field_map':{'a':'left','b':'right'},
                                             'inputs':{'left':17,'right':2}}))
            p=run('transfer',str(transfer))
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(json.loads(p.stdout)['output'],19)
            dataset=base/'private.json';dataset.write_text(json.dumps(eval_dataset()))
            public=base/'public.json';sub=base/'submission.json'; receipt=base/'receipt.json';qual=base/'qual.json'
            actions=[('eval-seal',str(dataset),str(public),'--vault',str(base/'vault.db')),
                     ('eval-candidate',str(public),str(sub)),
                     ('eval-score',str(public),str(sub),'--vault',str(base/'vault.db'),'--receipt',str(receipt)),
                     ('eval-qualify',str(public),str(receipt),'--vault',str(base/'vault.db'),'--qualification',str(qual)),
                     ('eval-verify-qualification',str(public),str(receipt),str(qual),'--vault',str(base/'vault.db'))]
            for command in actions:
                p=run(*command)
                self.assertEqual(p.returncode,0,command[0]+': '+p.stderr)
            self.assertEqual(json.loads(p.stdout)['status'],'policy_pass')

if __name__=='__main__': unittest.main()
