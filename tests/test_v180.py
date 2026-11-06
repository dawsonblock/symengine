"""v1.8 qualification / frozen snapshots / pseudo-label export regression suite."""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from sis.errors import InvalidInput, RuleRejected
from sis.service import Service
from sis.skill_bundle import validate_bundle, predict
from sis.validation import digest
from sis.skill_holdout import SkillHoldoutVault
from sis.distillation import export

ROOT=Path(__file__).resolve().parents[1]
KEY=b'custodian-key-only-32-bytes-minimum-XX'


def sample(a,b,c):
    return {'inputs':{'nums':[a,b,c]},'output':a+b+c}


def dataset():
    return {'study_id':'summation_v180','task_description':'Return the sum of the integers in nums.',
            'holdout':[sample(i,i%7,11) for i in range(30,70)],
            'shifted_holdout':[sample(-i,3,i%9) for i in range(80,120)],
            'excluded_inputs':[x['inputs'] for x in json.loads((ROOT/'examples/skill_sum_study.json').read_text())['train']],
            'policy':{'min_per_split':30,'min_coverage':0.95,'min_overall_accuracy':0.95,'min_wilson_lower':0.85}}


class HoldoutTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.s=Service(self.temp.name+'/skills.sqlite3')
        study=json.loads((ROOT/'examples/skill_sum_study.json').read_text())
        r=self.s.skill_study(study)
        self.assertEqual(r['promotion']['status'],'active')
        self.sid=r['promotion']['id']
        self.bundle=self.s.skill_freeze('list_sum',self.sid)
        self.vault=SkillHoldoutVault(self.temp.name+'/vault.sqlite3',key=KEY)
        self.dataset=dataset()

    def tearDown(self):
        self.vault.conn.close()
        self.s.registry.close()
        self.temp.cleanup()

    def evaluated(self):
        pub=self.vault.seal(self.dataset,self.bundle)
        receipt=self.vault.score(pub,self.bundle)
        return pub,receipt

    def test_baseline_full_pass_and_replay(self):
        pub,rec=self.evaluated()
        self.assertEqual(rec['assessment']['status'],'policy_pass')
        self.assertTrue(self.vault.verify(pub,self.bundle,rec)['replayed'])
        self.assertEqual(rec['metrics']['holdout']['correct'],40)
        self.assertEqual(rec['metrics']['shifted_holdout']['correct'],40)
        self.assertNotIn('inputs',json.dumps(pub))
        self.assertNotIn('nums',json.dumps(rec))
        self.assertNotIn('output',json.dumps(rec))

    def test_precommitted_bundle_cannot_change(self):
        pub=self.vault.seal(self.dataset,self.bundle)
        corrupted=copy.deepcopy(self.bundle)
        corrupted['skills'][0]['program']={'op':'const','value':7}
        with self.assertRaises(InvalidInput):self.vault.score(pub,corrupted)
        # Invalid submission does not burn one-use evaluation.
        receipt=self.vault.score(pub,self.bundle)
        self.assertEqual(receipt['assessment']['status'],'policy_pass')

    def test_one_use_after_success(self):
        pub,rec=self.evaluated()
        with self.assertRaises(RuleRejected):self.vault.score(pub,self.bundle)
        self.assertTrue(self.vault.verify(pub,self.bundle,rec)['valid'])

    def test_recover_committed_receipt_without_rescoring(self):
        pub,rec=self.evaluated()
        recovered=self.vault.recover_receipt(pub,self.bundle)
        self.assertEqual(recovered,rec)
        with self.assertRaises(RuleRejected):self.vault.score(pub,self.bundle)

    def test_recovery_requires_completed_scoring(self):
        pub=self.vault.seal(self.dataset,self.bundle)
        with self.assertRaises(RuleRejected):self.vault.recover_receipt(pub,self.bundle)

    def test_legacy_dataset_without_task_description_remains_supported(self):
        legacy=copy.deepcopy(self.dataset)
        legacy.pop('task_description')
        pub=self.vault.seal(legacy,self.bundle)
        private,_,_=self.vault._get(pub)
        self.assertTrue(private['task_description'])

    def test_cross_connection_one_use(self):
        pub,rec=self.evaluated()
        with SkillHoldoutVault(self.temp.name+'/vault.sqlite3',key=KEY) as other:
            with self.assertRaises(RuleRejected):other.score(pub,self.bundle)
            self.assertTrue(other.verify(pub,self.bundle,rec)['valid'])

    def test_public_manifest_tampering_fails(self):
        pub=self.vault.seal(self.dataset,self.bundle)
        tampered=copy.deepcopy(pub);tampered['policy']['min_coverage']=0
        with self.assertRaises(RuleRejected):self.vault.score(tampered,self.bundle)
        self.assertEqual(self.vault.score(pub,self.bundle)['assessment']['status'],'policy_pass')

    def test_receipt_tamper_fails(self):
        pub,rec=self.evaluated()
        rec['metrics']['holdout']['correct']=0
        with self.assertRaises(RuleRejected):self.vault.verify(pub,self.bundle,rec)

    def test_wrong_evaluator_secret_fails(self):
        pub,rec=self.evaluated()
        with SkillHoldoutVault(self.temp.name+'/vault.sqlite3',key=b'other-secret-at-least-thirty-two-byte!!') as wrong:
            with self.assertRaises(RuleRejected):wrong.verify(pub,self.bundle,rec)

    def test_private_database_tamper_fails(self):
        pub,rec=self.evaluated()
        self.vault.conn.execute('UPDATE sis_skill_holdout SET private=? WHERE id=?',('{}',pub['evaluation_id']))
        with self.assertRaises(RuleRejected):self.vault.verify(pub,self.bundle,rec)

    def test_overlap_between_splits_is_rejected(self):
        data=copy.deepcopy(self.dataset)
        data['shifted_holdout'][0]=copy.deepcopy(data['holdout'][0])
        with self.assertRaises(InvalidInput):self.vault.seal(data,self.bundle)

    def test_overlap_training_exclusions_is_rejected(self):
        data=copy.deepcopy(self.dataset)
        data['excluded_inputs'].append(data['holdout'][0]['inputs'])
        with self.assertRaises(InvalidInput):self.vault.seal(data,self.bundle)

    def test_small_holdout_is_rejected(self):
        data=copy.deepcopy(self.dataset);data['holdout']=data['holdout'][:3]
        with self.assertRaises(InvalidInput):self.vault.seal(data,self.bundle)

    def test_policy_failure_is_scored_without_promotion(self):
        data=copy.deepcopy(self.dataset)
        for c in data['shifted_holdout']:
            c['output']=123456
        pub=self.vault.seal(data,self.bundle)
        rec=self.vault.score(pub,self.bundle)
        self.assertEqual(rec['assessment']['status'],'policy_fail')
        self.assertTrue(self.vault.verify(pub,self.bundle,rec)['valid'])
        with self.assertRaises(RuleRejected):export(self.vault,pub,self.bundle,rec,[{'nums':[13,2,4]}])

    def test_frozen_bundle_survives_original_suspension(self):
        self.s.skill_feedback({'namespace':'list_sum','skill_id':self.sid,'inputs':{'nums':[2,2,2]},'observed_output':999})
        self.assertEqual(self.s.skill_predict({'namespace':'list_sum','inputs':{'nums':[4,3,2]}})['status'],'abstain')
        self.assertEqual(predict(self.bundle,{'nums':[4,3,2]}),9)
        self.assertEqual(self.vault.score(self.vault.seal(self.dataset,self.bundle),self.bundle)['assessment']['status'],'policy_pass')
        # Distinction: frozen artifact is NOT a claim that live skill remains active.
        with self.assertRaises(InvalidInput):self.s.skill_freeze('list_sum',self.sid)

    def test_bundle_manifest_and_hash_attacks(self):
        self.assertEqual(predict(self.bundle,{'nums':[3,5,7]}),15)
        for fn in (lambda b:b.update(bundle_digest='0'*64),
                   lambda b:b['skills'].append(copy.deepcopy(b['skills'][0])),
                   lambda b:b.update(root_skill_id='f'*64)):
            bundle=copy.deepcopy(self.bundle);fn(bundle)
            with self.assertRaises(InvalidInput):validate_bundle(bundle)

    def test_distillation_export_qualified_and_replayable(self):
        pub,rec=self.evaluated()
        inputs=[{'nums':[101,i,-i]} for i in range(1,6)]
        data,manifest=export(self.vault,pub,self.bundle,rec,inputs)
        self.assertEqual(len(data.splitlines()),5)
        self.assertEqual(manifest['count'],5)
        self.assertEqual(hashlib.sha256(data.encode()).hexdigest(),manifest['data_sha256'])
        self.vault._verify_signature(manifest)
        for line in data.splitlines():
            messages=json.loads(line)['messages']
            self.assertEqual(json.loads(messages[1]['content'])['task_description'],
                             self.dataset['task_description'])
            self.assertEqual(json.loads(messages[-1]['content']),{'output':101})
        self.assertNotIn('nums',json.dumps(manifest))

    def test_distillation_duplicates_and_holdout_overlap_fail(self):
        pub,rec=self.evaluated()
        item={'nums':[101,2,3]}
        with self.assertRaises(InvalidInput):export(self.vault,pub,self.bundle,rec,[item,item])
        with self.assertRaises(RuleRejected):export(self.vault,pub,self.bundle,rec,[self.dataset['holdout'][0]['inputs']])
        with self.assertRaises(RuleRejected):export(self.vault,pub,self.bundle,rec,[self.dataset['excluded_inputs'][0]])

    def test_wrong_schema_is_rejected(self):
        pub,rec=self.evaluated()
        with self.assertRaises(InvalidInput):export(self.vault,pub,self.bundle,rec,[{'nums':[1,2]}])

    def test_frozen_dependency_closure_and_missing_child(self):
        leaf_program={'op':'binary','fn':'add','left':{'op':'input','name':'a'},'right':{'op':'input','name':'b'}}
        leaf_schema={'a':'int','b':'int'}
        leaf_id=digest({'namespace':'example','schema':leaf_schema,'program':leaf_program})
        root_schema={'x':'int','y':'int'}
        root_program={'op':'call','skill_id':leaf_id,'args':{'a':{'op':'input','name':'x'},'b':{'op':'input','name':'y'}}}
        root_id=digest({'namespace':'example','schema':root_schema,'program':root_program})
        def record(sid,sch,prog):
            return {'id':sid,'namespace':'example','schema':sch,'program':prog,
                    'train_digest':'a'*64,'validation_digest':'b'*64,'train_count':3,'validation_count':2}
        body={'format':'sis.skill_bundle.v1','namespace':'example','root_skill_id':root_id,
              'audit_head':'c'*64,'skills':[record(leaf_id,leaf_schema,leaf_program),record(root_id,root_schema,root_program)]}
        bundle={**body,'bundle_digest':digest(body)}
        self.assertEqual(predict(bundle,{'x':9,'y':4}),13)
        body['skills'].pop(0)
        incomplete={**body,'bundle_digest':digest(body)}
        with self.assertRaises(InvalidInput):validate_bundle(incomplete)

    def test_skill_holdout_concurrent_single_claim(self):
        from concurrent.futures import ThreadPoolExecutor
        pub=self.vault.seal(self.dataset,self.bundle)
        def attempt(_):
            with SkillHoldoutVault(self.temp.name+'/vault.sqlite3',key=KEY) as v:
                try: return v.score(pub,self.bundle)['assessment']['status']
                except RuleRejected: return 'rejected'
        with ThreadPoolExecutor(max_workers=2) as ex:
            outcomes=list(ex.map(attempt,range(2)))
        self.assertCountEqual(outcomes,['policy_pass','rejected'])

    def test_cli_e2e_without_external_software(self):
        env={**os.environ,'PYTHONPATH':str(ROOT/'src'),'SIS_EVAL_HMAC_KEY':KEY.decode()}
        db=self.temp.name+'/skills.sqlite3'
        bundle_path=self.temp.name+'/bundle.json'
        private_path=self.temp.name+'/private.json'
        public_path=self.temp.name+'/public.json'
        receipt_path=self.temp.name+'/receipt.json'
        inputs_path=self.temp.name+'/inputs.json'
        output_path=self.temp.name+'/training.jsonl'
        for path,obj in ((private_path,self.dataset),(inputs_path,[{'nums':[101,9,1]}])):
            Path(path).write_text(json.dumps(obj))
        def run(*args):
            result=subprocess.run([sys.executable,'-m','sis','--db',db,*args],cwd=ROOT,env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr+' '+result.stdout)
        run('skill-freeze',self.sid,bundle_path,'--namespace','list_sum')
        run('skill-eval-seal',private_path,bundle_path,public_path,'--vault',self.temp.name+'/cli-vault.sqlite')
        run('skill-eval-score',public_path,bundle_path,receipt_path,'--vault',self.temp.name+'/cli-vault.sqlite')
        run('skill-eval-verify',public_path,bundle_path,receipt_path,'--vault',self.temp.name+'/cli-vault.sqlite')
        recovered=self.temp.name+'/recovered.json'
        run('skill-eval-recover',public_path,bundle_path,recovered,'--vault',self.temp.name+'/cli-vault.sqlite')
        self.assertEqual(json.loads(Path(recovered).read_text()),json.loads(Path(receipt_path).read_text()))
        run('skill-distill-export',public_path,bundle_path,receipt_path,inputs_path,output_path,'--vault',self.temp.name+'/cli-vault.sqlite')
        self.assertEqual(len(Path(output_path).read_text().splitlines()),1)
        self.assertTrue(Path(output_path+'.manifest.json').exists())
        # Repeated scoring must fail without clobbering prior receipt.
        proc=subprocess.run([sys.executable,'-m','sis','--db',db,'skill-eval-score',public_path,bundle_path,
                             self.temp.name+'/second.json','--vault',self.temp.name+'/cli-vault.sqlite'],cwd=ROOT,env=env,capture_output=True,text=True)
        self.assertEqual(proc.returncode,2)


if __name__=='__main__':unittest.main()
