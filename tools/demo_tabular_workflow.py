"""Self-contained data-agent capture demonstration; deterministic local data only.

Writes examples/v2_3 requests when --write-examples is supplied.
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

from sis.workflow_engine import WorkflowSession
from sis.service import Service


def dataset(a,b):
    return {'rows':[{'region':'east','amount':a},{'region':'west','amount':100},{'region':'east','amount':b}]}


def capture(a,b,reverse=False,redundant=False):
    session=WorkflowSession(dataset(a,b))
    filters=[{'op':'filter_eq','field':'region','value':'east'},
             {'op':'filter_gt','field':'amount','value':-1000}]
    if reverse: filters.reverse()
    if redundant: filters.append({'op':'filter_eq','field':'region','value':'east'})
    for command in filters + [{'op':'sum','field':'amount'}]:
        session.call(command)
    return session.capture()


def requests():
    train=[{'capture':capture(a,b,reverse=bool(i%2),redundant=bool(i==2)),
            'accepted':True,'expected_output':a+b}
           for i,(a,b) in enumerate([(1,2),(3,7),(10,-4),(8,19)])]
    validation=[{'data':dataset(a,b),'expected_output':a+b}
                for a,b in [(4,6),(9,-3),(15,20)]]
    return {'namespace':'tabular_demo','promote':True,
            'train_captures':train,'validation':validation}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--write-examples',action='store_true')
    args=ap.parse_args()
    study=requests()
    pred={'namespace':'tabular_demo','data':dataset(15,11)}
    if args.write_examples:
        target=Path(__file__).resolve().parents[1]/'examples'/'v2_3'
        target.mkdir(parents=True,exist_ok=True)
        (target/'workflow_study.json').write_text(json.dumps(study,indent=2)+'\n')
        (target/'workflow_predict.json').write_text(json.dumps(pred,indent=2)+'\n')
    with tempfile.TemporaryDirectory() as folder:
        service=Service(str(Path(folder)/'demo.sqlite3'))
        result=service.workflow_study(study)
        prediction=service.workflow_predict(pred)
        verified=service.workflow_audit()
        service.registry.close()
    if result['promotion']['status']!='active' or prediction['output']!=26 or verified['status']!='valid':
        raise RuntimeError('workflow demo failed')
    print(json.dumps({'status':'ok','promotion':result['promotion']['status'],
                      'training':result['training_count'],
                      'validation':result['validation_passed'],
                      'prediction':prediction['output'],
                      'audit':verified['status'],
                      'limits':'local, caller-labeled, read-only tabular skill learning'},indent=2))


if __name__=='__main__': main()
