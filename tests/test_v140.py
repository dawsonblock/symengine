"""v1.4.0 safety/regression checks. These are LOCAL tests, not outside holdouts."""
import copy
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from sis.errors import InvalidInput, RuleRejected
from sis.sealed_eval import EvaluatorVault, _mac, _metrics, _key_from_env
from sis.validation import digest

KEY = b'more_than_32_bytes_of_fixture_private_key_for_tests_only_2026'


def fixture():
    make = lambda xs: [{'inputs':{'x':x},'output':x+2} for x in xs]
    return {'task_id':'addition_shift', 'namespace':'arith',
            'train':make([-6,-2,0,3,5]), 'validation':make([7,9]),
            'test':make([11,15,25]), 'shifted_test':make([-100,1000])}


class TestVault(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'private.sqlite3'
        self.vault = EvaluatorVault(self.path,key=KEY)
        self.dataset = fixture()

    def tearDown(self):
        self.vault.close()
        self.tmp.cleanup()

    def prepare(self):
        public = self.vault.seal(self.dataset)
        res = EvaluatorVault.make_submission(public)
        self.assertEqual(res['status'],'candidate')
        return public, res['submission']

    def test_full_score_and_verify(self):
        public, candidate = self.prepare()
        result = self.vault.score(public,candidate)
        self.assertEqual(result['metrics']['test']['correct'],3)
        self.assertEqual(result['metrics']['shifted_test']['correct'],2)
        self.assertEqual(result['metrics']['test']['count'],3)
        self.assertEqual(self.vault.verify(public,result)['valid'],True)
        self.assertNotIn('test',public)
        self.assertNotIn('shifted_test',public)
        self.assertNotIn('secret',json.dumps(result))
        self.assertNotIn('inputs',json.dumps(result['metrics']))

    def test_replay_rejected_after_scoring(self):
        public,candidate = self.prepare()
        self.vault.score(public,candidate)
        with self.assertRaises(RuleRejected): self.vault.score(public,candidate)

    def test_replay_rejected_after_reopen(self):
        public,candidate = self.prepare()
        receipt = self.vault.score(public,candidate)
        self.vault.close()
        self.vault = EvaluatorVault(self.path,key=KEY)
        with self.assertRaises(RuleRejected): self.vault.score(public,candidate)
        self.assertTrue(self.vault.verify(public,receipt)['valid'])

    def test_recover_receipt_only_after_committed_score(self):
        public,candidate=self.prepare()
        with self.assertRaises(RuleRejected):
            self.vault.recover_receipt(public)
        receipt=self.vault.score(public,candidate)
        self.vault.close()
        self.vault=EvaluatorVault(self.path,key=KEY)
        recovered=self.vault.recover_receipt(public)
        self.assertEqual(recovered,receipt)
        self.assertTrue(self.vault.verify(public,recovered)['valid'])

    def test_invalid_candidate_does_not_consume(self):
        public,candidate = self.prepare()
        bad = copy.deepcopy(candidate)
        bad['rule'] = {'op':'const','value':8}
        with self.assertRaises(RuleRejected): self.vault.score(public,bad)
        self.assertEqual(self.vault.score(public,candidate)['metrics']['test']['correct'],3)

    def test_invalid_ast_does_not_consume(self):
        public,candidate = self.prepare()
        bad = copy.deepcopy(candidate)
        bad['rule'] = {'op':'eval','code':'print(999)'}
        with self.assertRaises(InvalidInput): self.vault.score(public,bad)
        self.assertEqual(self.vault.score(public,candidate)['metrics']['test']['correct'],3)

    def test_public_tampering_rejected(self):
        public,candidate = self.prepare()
        public['train'][0]['output'] = 1000
        with self.assertRaises(RuleRejected): self.vault.score(public,candidate)

    def test_bad_candidate_binding_rejected(self):
        public,candidate = self.prepare()
        candidate['public_digest'] = '0'*64
        with self.assertRaises(RuleRejected): self.vault.score(public,candidate)

    def test_wrong_evaluator_key_rejected(self):
        public,candidate = self.prepare()
        with EvaluatorVault(self.path,key=b'a'*32) as other:
            with self.assertRaises(RuleRejected): other.score(public,candidate)
        self.assertEqual(self.vault.score(public,candidate)['metrics']['test']['correct'],3)

    def test_secret_partition_tampering_rejected(self):
        public,candidate = self.prepare()
        original=self.vault.conn.execute('SELECT secret_json FROM tasks').fetchone()[0]
        corrupted=json.loads(original)
        corrupted['test'][0]['output'] = 999
        self.vault.conn.execute('UPDATE tasks SET secret_json=?',(json.dumps(corrupted),))
        with self.assertRaises(RuleRejected): self.vault.score(public,candidate)
        self.vault.conn.execute('UPDATE tasks SET secret_json=?',(original,))
        self.assertEqual(self.vault.score(public,candidate)['metrics']['test']['correct'],3)

    def test_verify_forged_receipt_rejected(self):
        public,candidate = self.prepare()
        receipt = self.vault.score(public,candidate)
        receipt['metrics']['test']['correct'] = 0
        with self.assertRaises(RuleRejected): self.vault.verify(public,receipt)

    def test_verify_modified_stored_receipt_rejected(self):
        public,candidate = self.prepare()
        receipt = self.vault.score(public,candidate)
        self.vault.conn.execute('UPDATE tasks SET receipt_json=?',(json.dumps({'bad':1}),))
        with self.assertRaises(RuleRejected): self.vault.verify(public,receipt)

    def test_no_duplicate_inputs_within_splits(self):
        self.dataset['test'][0] = copy.deepcopy(self.dataset['train'][0])
        with self.assertRaises(InvalidInput): self.vault.seal(self.dataset)

    def test_no_duplicate_inputs_across_evaluations(self):
        self.vault.seal(self.dataset)
        with self.assertRaises(RuleRejected): self.vault.seal(self.dataset)

    def test_rollback_after_duplicate_same_vault(self):
        self.vault.seal(self.dataset)
        with self.assertRaises(RuleRejected): self.vault.seal(self.dataset)
        self.assertEqual(self.vault.conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],1)

    def test_schema_mismatch_rejected(self):
        self.dataset['shifted_test'][0]['inputs']={'y':100}
        with self.assertRaises(InvalidInput): self.vault.seal(self.dataset)

    def test_output_type_mismatch_rejected(self):
        self.dataset['test'][0]['output']=True
        with self.assertRaises(InvalidInput): self.vault.seal(self.dataset)

    def test_too_small_shifted_set_rejected(self):
        self.dataset['shifted_test'] = self.dataset['shifted_test'][:1]
        with self.assertRaises(InvalidInput): self.vault.seal(self.dataset)

    def test_no_shifted_test_allowed(self):
        self.dataset.pop('shifted_test')
        public = self.vault.seal(self.dataset)
        submission=EvaluatorVault.make_submission(public)['submission']
        result=self.vault.score(public,submission)
        self.assertEqual(set(result['metrics']),{'test'})

    def test_public_does_not_reveal_private_labels(self):
        public=self.vault.seal(self.dataset)
        text=json.dumps(public,sort_keys=True)
        for case in self.dataset['test'] + self.dataset['shifted_test']:
            self.assertNotIn(json.dumps(case,sort_keys=True),text)
        self.assertEqual(len(public['test_commitment']),64)
        self.assertNotEqual(public['test_commitment'],digest(self.dataset['test']))

    def test_unauthorized_dataset_fields_rejected(self):
        self.dataset['evaluation_override']='trust_me'
        with self.assertRaises(InvalidInput): self.vault.seal(self.dataset)

    def test_repeated_parallel_candidates_exactly_one_success(self):
        public,candidate = self.prepare()
        self.vault.close()
        self.vault = EvaluatorVault(self.path,key=KEY)
        result=[]
        barrier=threading.Barrier(3)
        def worker():
            with EvaluatorVault(self.path,key=KEY) as v:
                barrier.wait()
                try:
                    v.score(public,candidate)
                    result.append('success')
                except RuleRejected:
                    result.append('rejected')
        a=threading.Thread(target=worker)
        b=threading.Thread(target=worker)
        a.start();b.start();barrier.wait();a.join(timeout=20);b.join(timeout=20)
        self.assertEqual(sorted(result),['rejected','success'])

    def test_metrics_count_runtime_abstentions(self):
        records=[{'inputs':{'x':3},'output':5},{'inputs':{'x':4},'output':6}]
        rule={'op':'item','name':'x','index':0}
        m=_metrics(rule, records, '5')
        self.assertEqual(m['answered'],0)
        self.assertEqual(m['abstained'],2)
        self.assertIsNone(m['accuracy_on_answered'])

    def test_custodian_key_mandatory(self):
        old=os.environ.pop('TEST_NONEXISTENT_SIS_EVAL_KEY',None)
        try:
            with self.assertRaises(RuleRejected): _key_from_env('TEST_NONEXISTENT_SIS_EVAL_KEY')
        finally:
            if old: os.environ['TEST_NONEXISTENT_SIS_EVAL_KEY']=old

    def test_existing_public_or_symlink_vault_is_rejected(self):
        if os.name != 'posix':
            self.skipTest('POSIX permission and symlink checks')
        exposed=self.path.parent/'exposed.sqlite3'
        exposed.write_bytes(b'')
        exposed.chmod(0o640)
        with self.assertRaises(InvalidInput):
            EvaluatorVault(exposed,key=KEY)
        linked=self.path.parent/'linked.sqlite3'
        linked.symlink_to(exposed)
        with self.assertRaises(InvalidInput):
            EvaluatorVault(linked,key=KEY)

    def test_receipt_does_not_claim_external_independence(self):
        public,candidate = self.prepare()
        receipt=self.vault.score(public,candidate)
        self.assertIn('require external custody',receipt['statement'])

    def test_unsigned_public_rejected(self):
        public,candidate = self.prepare()
        public.pop('seal_mac')
        with self.assertRaises(RuleRejected): self.vault.score(public,candidate)

    def test_no_candidate_from_insufficient_fit(self):
        public,candidate = self.prepare()
        public=copy.deepcopy(public)
        public['train']=[{'inputs':{'x':a}, 'output':v} for a,v in [(-3,1),(-2,3),(-1,4),(0,99)]]
        response=EvaluatorVault.make_submission(public)
        self.assertEqual(response['status'],'no_qualified_candidate')


class TestCli(unittest.TestCase):
    def test_cli_evaluator_full_workflow(self):
        with tempfile.TemporaryDirectory() as td:
            td=Path(td)
            (td/'dataset.json').write_text(json.dumps(fixture()),encoding='utf8')
            env={**os.environ,'SIS_EVAL_HMAC_KEY':KEY.decode('utf8'),
                 'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
            def run(*args, expect=0):
                cmd=[sys.executable,'-m','sis','--db',str(td/'irrelevant.sqlite3'),*args]
                res=subprocess.run(cmd,env=env,cwd=td,capture_output=True,text=True,timeout=20)
                self.assertEqual(res.returncode,expect,f'{cmd}: {res.stderr}')
                return res
            run('eval-seal',str(td/'dataset.json'),str(td/'public.json'),'--vault',str(td/'vault.sqlite3'))
            run('eval-recover',str(td/'public.json'),'--vault',str(td/'vault.sqlite3'),
                '--receipt',str(td/'early-receipt.json'),expect=2)
            self.assertFalse((td/'early-receipt.json').exists())
            run('eval-candidate',str(td/'public.json'),str(td/'candidate.json'))
            run('eval-score',str(td/'public.json'),str(td/'candidate.json'),'--vault',str(td/'vault.sqlite3'),'--receipt',str(td/'receipt.json'))
            run('eval-recover',str(td/'public.json'),'--vault',str(td/'vault.sqlite3'),
                '--receipt',str(td/'recovered.json'))
            self.assertEqual(json.loads((td/'recovered.json').read_text()),
                             json.loads((td/'receipt.json').read_text()))
            output=run('eval-verify',str(td/'public.json'),str(td/'receipt.json'),'--vault',str(td/'vault.sqlite3'))
            self.assertTrue(json.loads(output.stdout)['valid'])
            run('eval-score',str(td/'public.json'),str(td/'candidate.json'),'--vault',str(td/'vault.sqlite3'),'--receipt',str(td/'receipt2.json'),expect=2)
            self.assertFalse((td/'receipt2.json').exists())
            run('eval-candidate',str(td/'public.json'),str(td/'candidate.json'),expect=2)


if __name__=='__main__': unittest.main()
