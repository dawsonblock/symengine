#!/usr/bin/env python3
"""One-process demo only: NOT an independent evaluator or hidden dataset."""
import json
import secrets
import tempfile
from pathlib import Path
from sis.service import Service
from sis.skill_holdout import SkillHoldoutVault
from sis.distillation import export

ROOT=Path(__file__).resolve().parents[1]

def sample(a,b,c):
    return {'inputs':{'nums':[a,b,c]},'output':a+b+c}


def main():
    with tempfile.TemporaryDirectory(prefix='sis-v180-demo-') as directory:
        with_service=Service(str(Path(directory)/'skills.db'))
        try:
            study=json.loads((ROOT/'examples/skill_sum_study.json').read_text())
            induction=with_service.skill_study(study)
            sid=induction['promotion']['id']
            bundle=with_service.skill_freeze('list_sum',sid)
        finally:
            with_service.registry.close()
        data={'study_id':'synthetic_list_sum_demo','task_description':'Return the sum of the integers in nums.',
              'holdout':[sample(i,i%7,11) for i in range(30,70)],
              'shifted_holdout':[sample(-i,3,i%9) for i in range(80,120)],
              'excluded_inputs':[row['inputs'] for row in study['train']+study['validation']],
              'policy':{'min_per_split':30,'min_coverage':0.95,
                        'min_overall_accuracy':0.95,'min_wilson_lower':0.85}}
        with SkillHoldoutVault(str(Path(directory)/'evaluator.db'),key=secrets.token_bytes(32)) as vault:
            public=vault.seal(data,bundle)
            receipt=vault.score(public,bundle)
            proof=vault.verify(public,bundle,receipt)
            data_jsonl,manifest=export(vault,public,bundle,receipt,[{'nums':[101,i,-i]} for i in range(1,6)])
            print(json.dumps({'induction_status':induction['status'],
                  'snapshot_digest':bundle['bundle_digest'],
                  'holdout':receipt['metrics']['holdout'],
                  'shifted_holdout':receipt['metrics']['shifted_holdout'],
                  'assessment':proof['assessment'],
                  'replayed':proof['replayed'],
                  'distillation_records':manifest['count'],
                  'warnings':['synthetic arithmetic examples only',
                    'same process controls both candidate and evaluator; NOT independent evidence',
                    'exported examples contain skill-generated pseudo-labels']},indent=2))

if __name__=='__main__':main()
