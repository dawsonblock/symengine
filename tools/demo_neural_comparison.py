#!/usr/bin/env python3
"""Deterministic model mocks only. No weight training or external API calls."""
import json
from sis.neural_eval import evaluate
from sis.validation import canonical, digest


def frozen_identity():
    program={'op':'input','name':'a'}
    schema={'a':'int','b':'int'}
    sid=digest({'namespace':'demo','schema':schema,'program':program})
    row={'id':sid,'namespace':'demo','schema':schema,'program':program,
         'train_digest':'a'*64,'validation_digest':'b'*64,'train_count':4,'validation_count':2}
    body={'format':'sis.skill_bundle.v1','namespace':'demo','root_skill_id':sid,'audit_head':'c'*64,'skills':[row]}
    return {**body,'bundle_digest':digest(body)}


class ModelMock:
    def __init__(self, learned=False):self.learned=learned
    def complete_with_metadata(self, messages, max_tokens):
        request=json.loads(messages[1]['content'])
        hint=request.get('sis_prediction',{})
        target=request['inputs']['a'] if self.learned else hint.get('output',-1)
        return canonical({'output':target}), {'total_tokens':30}


if __name__=='__main__':
    dataset={'namespace':'demo','task_description':'Return the value in input field a.',
             'cases':[{'inputs':{'a':i,'b':2},'output':i} for i in range(10,30)],
             'excluded_inputs':[{'a':1,'b':2}], 'max_tokens':64,'include_placebo':True}
    result=evaluate(dataset,frozen_identity(),ModelMock(),ModelMock(learned=True),
                    baseline_label='synthetic-mock',distilled_label='synthetic-mock-adapted')
    print(json.dumps({'status':result['status'],'cases':result['count'],'arms':result['arms'],
                      'comparisons':result['vs_baseline'], 'warning':'Synthetic mocks; these are not actual LLM outcomes'},indent=2))
