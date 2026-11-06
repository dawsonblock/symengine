"""v2.0 evaluator precommit, split leakage, replay prevention, and statistical checks."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from sis.errors import InvalidInput, RuleRejected
from sis.family_eval import (DATASET_FORMAT,precommit,validate_dataset,validate_protocol,
    evaluate,holm_adjust,FamilyExperimentVault,verify_report)
from sis.validation import canonical,digest

KEY=b'evaluator-owned-secret-key-with-adequate-entropy-for-tests'


def fixture():
    schema={'a':'int','b':'int'}
    ast={'op':'input','name':'a'}
    sid=digest({'namespace':'calc','schema':schema,'program':ast})
    rec={'id':sid,'namespace':'calc','schema':schema,'program':ast,
         'train_digest':'a'*64,'validation_digest':'b'*64,'train_count':4,'validation_count':3}
    obj={'format':'sis.skill_bundle.v1','namespace':'calc','root_skill_id':sid,
         'audit_head':'c'*64,'skills':[rec]}
    obj['bundle_digest']=digest(obj)
    data={'format':DATASET_FORMAT,'experiment_id':'trial-001','namespace':'calc',
          'task_description':'Return the value in field a.',
          'test':[{'family_id':f'family-{k}', 'cases':[
              {'inputs':{'a':k*100+i+1,'b':2},'output':k*100+i+1} for i in range(8)]}
                  for k in range(8)],
          'training_families':['train-family'], 'validation_families':['valid-family'],
          'excluded_inputs':[{'a':-1,'b':2}], 'max_tokens':64,'include_placebo':True}
    return data,obj


class Dumb:
    def complete(self,messages,max_tokens):
        return canonical({'output':0})


class Assisted:
    def complete(self,messages,max_tokens):
        req=json.loads(messages[-1]['content'])
        hint=req.get('sis_prediction',{})
        return canonical({'output':hint['output'] if hint.get('status')=='available' else 0})


class Adapted:
    def complete(self,messages,max_tokens):
        req=json.loads(messages[-1]['content'])
        return canonical({'output':req['inputs']['a']})


class OfflineModel:
    """Base model that uses a tentative SIS hint only when one is provided."""
    def complete(self,messages,max_tokens):
        req=json.loads(messages[-1]['content'])
        hint=req.get('sis_prediction',{})
        return canonical({'output':hint['output'] if hint.get('status')=='available' else 0})


class TestProtocol(unittest.TestCase):
    def setUp(self): self.data,self.bundle=fixture()

    def seal(self):
        return precommit(self.data,self.bundle,key=KEY,baseline_id='base@sha',adapted_id='lora@sha')

    def test_precommit_no_gold_or_raw_inputs(self):
        p=self.seal()
        self.assertTrue(validate_protocol(p,self.data,self.bundle,key=KEY))
        self.assertNotIn('cases',p)
        self.assertNotIn('output',canonical(p))

    def test_authentication_and_test_tampering_fail(self):
        p=self.seal()
        tampered=copy.deepcopy(self.data);tampered['test'][0]['cases'][0]['output']=-42
        with self.assertRaises(RuleRejected):validate_protocol(p,tampered,self.bundle,key=KEY)
        p['policy']['minimum_gain']=0
        with self.assertRaises(RuleRejected):validate_protocol(p,self.data,self.bundle,key=KEY)

    def test_wrong_key_and_missing_key_fail(self):
        p=self.seal()
        with self.assertRaises(RuleRejected):validate_protocol(p,self.data,self.bundle,key=b'X'*32)
        with self.assertRaises(InvalidInput):self.seal_with_key(b'x')

    def seal_with_key(self,key):
        return precommit(self.data,self.bundle,key=key,baseline_id='base',adapted_id='adapted')

    def test_family_leakage(self):
        self.data['training_families']=['family-0']
        with self.assertRaises(InvalidInput): self.seal()

    def test_validation_family_leakage(self):
        self.data['validation_families']=['train-family']
        with self.assertRaises(InvalidInput): self.seal()

    def test_duplicate_across_groups(self):
        self.data['test'][1]['cases'][0]['inputs']=self.data['test'][0]['cases'][0]['inputs']
        with self.assertRaises(InvalidInput): self.seal()

    def test_training_input_overlap(self):
        self.data['excluded_inputs'].append(self.data['test'][0]['cases'][0]['inputs'])
        with self.assertRaises(InvalidInput): self.seal()

    def test_schema_change(self):
        self.data['test'][0]['cases'][0]['inputs']={'a':5}
        with self.assertRaises(InvalidInput): self.seal()

    def test_underpowered_family(self):
        self.data['test'][0]['cases']=self.data['test'][0]['cases'][:7]
        with self.assertRaises(InvalidInput): self.seal()

    def test_require_placebo(self):
        self.data['include_placebo']=False
        with self.assertRaises(InvalidInput):self.seal()
        protocol=precommit(self.data,self.bundle,key=KEY,baseline_id='base',adapted_id='adapted',policy={
            'alpha':0.05,'minimum_gain':0.05,'require_placebo_win':False})
        self.assertFalse(protocol['include_placebo'])

    def test_invalid_policy(self):
        for policy in ({'alpha':float('nan'),'minimum_gain':0.05,'require_placebo_win':True},
                       {'alpha':0.05,'minimum_gain':False,'require_placebo_win':True}):
            with self.assertRaises(InvalidInput):precommit(self.data,self.bundle,key=KEY,
                baseline_id='base',adapted_id='adapted',policy=policy)

    def test_holm_stepdown_monotone(self):
        vals=holm_adjust({'a':0.005,'b':0.02,'c':0.9})
        self.assertAlmostEqual(vals['a'],0.015)
        self.assertAlmostEqual(vals['b'],0.04)
        self.assertEqual(vals['c'],0.9)

    def test_end_to_end_qualification_and_label_isolation(self):
        protocol=self.seal()
        result=evaluate(self.data,protocol,self.bundle,OfflineModel(),Adapted(),key=KEY)
        self.assertEqual(result['status'],'evaluated')
        self.assertEqual(result['qualification']['status'],'policy_pass')
        self.assertEqual(result['family_count'],8)
        self.assertEqual(result['case_count'],64)
        self.assertFalse(result['gold_labels_sent_to_model'])
        self.assertEqual(result['arms']['baseline']['accuracy'],0)
        self.assertEqual(result['arms']['symbolic']['accuracy'],1)
        self.assertEqual(result['arms']['adapted']['accuracy'],1)
        self.assertEqual(result['arms']['placebo']['accuracy'],0)
        self.assertLess(result['comparisons']['symbolic']['family_holm_adjusted_p'],0.05)
        self.assertNotIn('cases',canonical(result))

    def test_task_description_reaches_every_model_arm(self):
        seen=[]
        class Capture:
            def complete(self,messages,max_tokens):
                seen.append(json.loads(messages[-1]['content']))
                return canonical({'output':0})
        class CaptureAdapted:
            def complete(self,messages,max_tokens):
                seen.append(json.loads(messages[-1]['content']))
                return canonical({'output':0})
        evaluate(self.data,self.seal(),self.bundle,Capture(),CaptureAdapted(),key=KEY)
        self.assertEqual(len(seen),sum(len(family['cases']) for family in self.data['test'])*4)
        self.assertTrue(all(item['task_description']==self.data['task_description'] for item in seen))

    def test_report_replay_signature(self):
        p=self.seal()
        report=evaluate(self.data,p,self.bundle,OfflineModel(),Adapted(),key=KEY)
        self.assertTrue(verify_report(report,p,key=KEY)['valid'])
        altered=copy.deepcopy(report);altered['arms']['baseline']['accuracy']=0.9
        with self.assertRaises(RuleRejected):verify_report(altered,p,key=KEY)
        altered=copy.deepcopy(p);altered['experiment_id']='forged'
        with self.assertRaises(RuleRejected):verify_report(report,altered,key=KEY)

    def test_correlated_item_gain_cannot_pass_family_gate(self):
        # Each model gets 8 improvements, clustered in exactly one family.
        # Item-level McNemar p<0.05, family-level Holm p>=0.05.
        class Narrow:
            def complete(self,messages,max_tokens):
                user=json.loads(messages[-1]['content'])
                inp=user['inputs']['a']
                hint=user.get('sis_prediction',{})
                return canonical({'output':hint['output'] if hint.get('status')=='available' else
                                  (0 if inp<100 else inp)})
        class AdaptNarrow:
            def complete(self,messages,max_tokens):
                user=json.loads(messages[-1]['content'])
                return canonical({'output':user['inputs']['a']})
        report=evaluate(self.data,self.seal(),self.bundle,Narrow(),AdaptNarrow(),key=KEY)
        self.assertLess(report['comparisons']['symbolic']['holm_adjusted_p'],0.05)
        self.assertGreater(report['comparisons']['symbolic']['family_holm_adjusted_p'],0.05)
        self.assertEqual(report['qualification']['status'],'policy_fail')

    def test_cli_precommit_auth(self):
        import os,sys,subprocess
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as t:
            a=Path(t)/'data.json';b=Path(t)/'bundle.json';c=Path(t)/'protocol.json'
            a.write_text(canonical(self.data));b.write_text(canonical(self.bundle))
            env=dict(os.environ);env['PYTHONPATH']=str(root/'src');env['SIS_EVAL_HMAC_KEY']=KEY.decode()
            cmd=[sys.executable,'-m','sis','family-eval-seal',str(a),str(b),str(c),
                 '--baseline-id','base@sha','--adapted-id','lora@sha']
            run=subprocess.run(cmd,env=env,capture_output=True,text=True,cwd=root,timeout=20)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertTrue(validate_protocol(json.loads(c.read_text()),self.data,self.bundle,key=KEY))
            rerun=subprocess.run(cmd,env=env,capture_output=True,text=True,cwd=root,timeout=20)
            self.assertNotEqual(rerun.returncode,0)

    def test_model_errors_fail_closed(self):
        class Broken:
            def complete(self,messages,max_tokens): raise OSError('offline')
        report=evaluate(self.data,self.seal(),self.bundle,Broken(),Adapted(),key=KEY)
        self.assertEqual(report['status'],'invalid_model_errors')
        self.assertEqual(report['qualification']['status'],'policy_fail')

    def test_no_gain_fails(self):
        report=evaluate(self.data,self.seal(),self.bundle,Adapted(),Adapted(),key=KEY)
        self.assertEqual(report['qualification']['status'],'policy_fail')

    def test_once_only_spent_even_if_error(self):
        with tempfile.TemporaryDirectory() as d:
            with_vault=FamilyExperimentVault(Path(d)/'vault.sqlite3')
            try:
                p=self.seal()
                report=with_vault.run(self.data,p,self.bundle,OfflineModel(),Adapted(),key=KEY)
                self.assertEqual(with_vault.get_status('trial-001')['status'],'complete')
                with self.assertRaises(RuleRejected):with_vault.run(self.data,p,self.bundle,OfflineModel(),Adapted(),key=KEY)
                self.assertEqual(with_vault.get_status('trial-001')['report_hash'],digest(report))
            finally:with_vault.close()

    def test_vault_reserve_before_model_calls(self):
        class Crashes(BaseException):pass
        class Exploding:
            def complete(self,messages,max_tokens):raise Crashes()
        with tempfile.TemporaryDirectory() as d:
            v=FamilyExperimentVault(Path(d)/'e.sqlite3')
            try:
                with self.assertRaises(Crashes):v.run(self.data,self.seal(),self.bundle,Exploding(),Adapted(),key=KEY)
                self.assertEqual(v.get_status('trial-001')['status'],'reserved')
                with self.assertRaises(RuleRejected):v.run(self.data,self.seal(),self.bundle,OfflineModel(),Adapted(),key=KEY)
            finally:v.close()


if __name__=='__main__':unittest.main()
