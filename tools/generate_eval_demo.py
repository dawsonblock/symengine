#!/usr/bin/env python3
"""Create a *synthetic, fully known* demo dataset. NOT independent evidence."""
import json
import os
import stat
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python tools/generate_eval_demo.py OUTPUT_DIRECTORY')
    dest = Path(sys.argv[1])
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == 'posix' and stat.S_IMODE(dest.stat().st_mode) & 0o077:
        raise SystemExit('OUTPUT_DIRECTORY must deny group and other access for evaluator vault use')
    path = dest/'dataset.json'
    def examples(values):
        return [{'inputs':{'x':value},'output':value+2} for value in values]
    data = {
        'namespace':'arith','task_id':'SYNTHETIC_ADD_TWO_DEMO_NOT_EXTERNAL',
        'train':examples([-6,-2,0,3,5]),
        'validation':examples([7,9]),
        'test':examples([11,15,25]),
        'shifted_test':examples([-100,1000]),
    }
    with path.open('x',encoding='utf8') as stream:
        json.dump(data,stream,indent=2)
        stream.write('\n')
    print(json.dumps({'path':str(path),'qualification':'SYNTHETIC LOCAL DEMO; NO INDEPENDENT HOLDOUT'},indent=2))

if __name__=='__main__':
    main()
