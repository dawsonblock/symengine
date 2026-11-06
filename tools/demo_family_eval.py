#!/usr/bin/env python3
"""Synthetic offline v2.0 demonstration, NOT evidence of LLM improvement."""
import json
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from sis.validation import digest,canonical
from sis.family_eval import (DATASET_FORMAT,FamilyExperimentVault,evaluate,precommit)

KEY=b'local-demo-key-not-independent-evaluator-secret'

class FakeBase:
    def complete(self,messages,max_tokens):
        user=json.loads(messages[-1]['content'])
        hint=user.get('sis_prediction',{})
        answer=hint['output'] if hint.get('status')=='available' else 0
        return canonical({'output':answer})

class FakeAdapted:
    def complete(self,messages,max_tokens):
        user=json.loads(messages[-1]['content'])
        return canonical({'output':user['inputs']['a']})


def main():
    schema={'a':'int','b':'int'}
    program={'op':'input','name':'a'}
    skill_id=digest({'namespace':'demo','schema':schema,'program':program})
    record={'id':skill_id,'namespace':'demo','schema':schema,'program':program,
            'train_digest':'a'*64,'validation_digest':'b'*64,'train_count':8,'validation_count':4}
    bundle={'format':'sis.skill_bundle.v1','namespace':'demo','root_skill_id':skill_id,
            'audit_head':'c'*64,'skills':[record]}
    bundle['bundle_digest']=digest(bundle)
    data={'format':DATASET_FORMAT,'experiment_id':'synthetic-v2-example','namespace':'demo',
          'task_description':'Return the value in input field a.',
          'test':[{'family_id':f'family-{group}','cases':[
              {'inputs':{'a':100*group+i+1,'b':2},'output':100*group+i+1} for i in range(8)]}
              for group in range(8)],
          'training_families':['synthetic-train'],
          'validation_families':['synthetic-validation'],
          'excluded_inputs':[{'a':-10,'b':2}],
          'max_tokens':64,'include_placebo':True}
    protocol=precommit(data,bundle,key=KEY,baseline_id='fake-baseline',adapted_id='fake-adapted')
    with tempfile.TemporaryDirectory() as tmp:
        vault=FamilyExperimentVault(Path(tmp)/'custodian-demo.sqlite3')
        try:
            report=vault.run(data,protocol,bundle,FakeBase(),FakeAdapted(),key=KEY)
        finally:
            vault.close()
    print(json.dumps({'demo_only':True,'family_count':report['family_count'],
        'case_count':report['case_count'],'arms':report['arms'],
        'qualification':report['qualification'],
        'warning':'DETERMINISTIC SYNTHETIC MOCKS; NO ACTUAL LLM WAS TESTED'},indent=2))

if __name__=='__main__':main()
