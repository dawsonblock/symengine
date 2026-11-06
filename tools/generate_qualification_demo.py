#!/usr/bin/env python3
"""Generate synthetic large-sample policy demo (never external validation)."""
import json
import sys
from pathlib import Path


def main():
    if len(sys.argv)!=2:
        raise SystemExit('Usage: python tools/generate_qualification_demo.py OUTPUT_DIRECTORY')
    out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
    def make(seq): return [{'inputs':{'x':x},'output':x+2} for x in seq]
    data={'namespace':'arith','task_id':'SYNTHETIC_QUALIFICATION_DEMO',
          'train':make([-6,-2,0,3,5]),'validation':make([7,9,13]),
          'test':make(range(100,140)),'shifted_test':make(range(-250,-210))}
    dest=out/'dataset.json'
    with dest.open('x',encoding='utf8') as stream:
        stream.write(json.dumps(data,indent=2)+'\n')
    print(json.dumps({'dataset':str(dest),'qualification':'SYNTHETIC LOCAL FIXTURE; a pass is NOT independent evidence'},indent=2))


if __name__=='__main__':main()
