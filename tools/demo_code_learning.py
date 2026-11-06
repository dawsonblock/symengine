#!/usr/bin/env python3
"""Exercise v2.4 full code capture -> guarded study -> read-only preview.

All snippets are pure arithmetic. No Python source is executed or written.
"""
from pathlib import Path
import json
import tempfile
from sis.service import Service
from sis.code_learning import capture_repair
from sis.bridge import ToolBridge

RECIPE={'kind':'binary_operator_swap','from_op':'Sub','to_op':'Add'}


def example(name,left,right,filename):
    source=f'def {name}({left}, {right}):\n    return {left} - {right}\n'
    cases=[{'args':{left:a,right:b},'expected':a+b}
           for a,b in ((2,3),(7,-2),(10,15))]
    return {'source':source,'filename':filename,'function':name,'cases':cases}


def demonstrate():
    tr=[example('total','a','b','one.py'),
        example('combine','x','y','two.py'),
        example('merge','lhs','rhs','three.py')]
    train=[capture_repair({**item,'recipe':RECIPE}) for item in tr]
    validation=[example('accumulate','c','d','four.py'),
                example('plus','first','second','five.py')]
    with tempfile.TemporaryDirectory() as td:
        service=Service(str(Path(td)/'demo.sqlite3'))
        try:
            result=service.code_study({'namespace':'repair_demo','promote':True,
                                       'train_captures':train,'validation':validation})
            if result['status']!='locally_validated':
                raise RuntimeError('demonstration did not qualify')
            preview=ToolBridge(service).invoke('sis_code_preview',
                     {'namespace':'repair_demo','source':'def future(a, b):\n    return a - b\n',
                      'filename':'future.py','function':'future'})
            audit=service.code_audit()
            if audit['status']!='valid' or preview['status']!='preview' or 'a + b' not in preview['patched_source']:
                raise RuntimeError('demonstration check failed')
            return {'qualification':result['status'],'training':result['training_count'],
                    'holdouts':result['validation_passed'],
                    'promotion':result['promotion'],'preview_diff':preview['diff'],
                    'audit':audit,'source_execution':'none; AST interpretation only'}
        finally:
            service.registry.close()

if __name__=='__main__':
    print(json.dumps(demonstrate(),indent=2))
