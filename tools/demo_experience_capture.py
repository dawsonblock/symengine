"""Executable demo of capturing an agent's tool calls and learning from experience.

This creates synthetic examples by executing the actual pure SIS tool boundary;
independent labels are supplied by a deterministic demonstration oracle.
"""
import json
import tempfile
from pathlib import Path
from sis.service import Service
from sis.experience_events import InstrumentedSession, replay_capture


def capture(a,b):
    session=InstrumentedSession({'a':a,'b':b})
    total=session.call('add',left=session.input('a'),right=session.input('b'),step_id='sum')
    session.call('mul',left=total,right=session.literal(2),step_id='double')
    return session.capture()


def main():
    train=[]
    for a,b in [(1,2),(5,-2),(-3,7),(11,13),(9,12)]:
        record=capture(a,b)
        assert replay_capture(record)['observed_output']==2*(a+b)
        train.append({'capture':record,'accepted':True})
    validation=[{'inputs':{'a':7,'b':8},'output':30},
                {'inputs':{'a':-10,'b':6},'output':-8},
                {'inputs':{'a':20,'b':0},'output':40}]
    with tempfile.TemporaryDirectory() as tmp:
        svc=Service(str(Path(tmp)/'skills.sqlite3'))
        try:
            result=svc.experience_induce({'namespace':'observed_demo',
                  'promote':True,'train_captures':train,'validation':validation})
            pred=svc.skill_predict({'namespace':'observed_demo','inputs':{'a':15,'b':11}})
            audit=svc.skill_audit()
            print(json.dumps({'learning_status':result['status'],
                  'promotion':result.get('promotion'),
                  'capture_evidence':result['abstraction'],
                  'prediction':pred,'audit':audit}, indent=2))
            assert result['status']=='locally_validated', result
            assert result['promotion']['status']=='active'
            assert pred['output']==52 and audit['valid']
        finally:
            svc.registry.close()

if __name__=='__main__':
    main()
