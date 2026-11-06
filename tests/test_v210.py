"""v2.1 trace replay, train-only proposals, and existing authority gating."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sis.errors import InvalidInput
from sis.trace_learning import compile_trace, transform_traces
from sis.service import Service

ROOT = Path(__file__).resolve().parents[1]


def var(name): return {'op':'var','name':name}
def inp(name): return {'op':'input','name':name}
def twice_sum(a,b): return (a+b)*2


def steps(a,b):
    return [
        {'name':'total','expr':{'op':'binary','fn':'add','left':inp('a'),'right':inp('b')},'value':a+b},
        {'name':'double','expr':{'op':'binary','fn':'mul','left':var('total'),'right':{'op':'const','value':2}},'value':twice_sum(a,b)},
    ]


def request():
    train=[]
    for a,b in [(1,2),(5,-2),(-3,7),(11,13)]:
        train.append({'inputs':{'a':a,'b':b},'observed_output':twice_sum(a,b),
                      'accepted':True,'steps':steps(a,b)})
    validation=[{'inputs':{'a':a,'b':b},'observed_output':twice_sum(a,b),'accepted':True}
                for a,b in [(7,8),(-10,6),(20,0)]]
    return {'namespace':'trace_calc','train_episodes':train,
            'validation_episodes':validation,'promote':True}


class TestTraceCompile(unittest.TestCase):
    def test_multistep_compilation(self):
        program=compile_trace(steps(2,3),{'a':2,'b':3})
        from sis.skill_program import execute
        self.assertEqual(execute(program,{'a':10,'b':11}),42)
    def test_tampered_intermediate_value(self):
        trace=steps(2,3);trace[0]['value']=999
        with self.assertRaises(InvalidInput):compile_trace(trace,{'a':2,'b':3})
    def test_boolean_not_integer(self):
        trace=steps(2,3);trace[1]['value']=True
        with self.assertRaises(InvalidInput):compile_trace(trace,{'a':2,'b':3})
    def test_forward_and_undefined_references(self):
        bad=steps(2,3);bad[0]['expr']=var('double')
        with self.assertRaises(InvalidInput):compile_trace(bad,{'a':2,'b':3})
    def test_duplicate_names(self):
        bad=steps(2,3);bad[1]['name']='total'
        with self.assertRaises(InvalidInput):compile_trace(bad,{'a':2,'b':3})
    def test_unknown_structure_and_unbounded(self):
        for trace in ([{}], steps(2,3)*4, [{'name':'x','expr':{'op':'python','code':'1+1'},'value':2}]):
            with self.subTest(trace=trace),self.assertRaises(InvalidInput):compile_trace(trace,{'a':2,'b':3})
    def test_call_not_executed(self):
        trace=[{'name':'x','expr':{'op':'call','skill_id':'a'*64,'args':{'a':inp('a')}},'value':1}]
        with self.assertRaises(InvalidInput):compile_trace(trace,{'a':2,'b':3})


class TestTraceTransform(unittest.TestCase):
    def test_only_train_promotes_and_validated(self):
        study,info=transform_traces(request())
        self.assertEqual(info['trace_programs'],1)
        self.assertEqual(info['trace_steps_replayed'],8)
        self.assertEqual(len(study['proposals']),1)
        self.assertEqual(len(study['validation']),3)
    def test_validation_step_leakage_forbidden(self):
        req=request();req['validation_episodes'][0]['steps']=steps(7,8)
        with self.assertRaises(InvalidInput):transform_traces(req)
    def test_tampered_observed_output_rejected(self):
        req=request();req['train_episodes'][0]['observed_output']=999
        with self.assertRaises(InvalidInput):transform_traces(req)
    def test_failed_trace_cannot_be_promoted(self):
        req=request()
        row=req['train_episodes'][0]
        row['accepted']=False
        row['correct_output']=999 # corrected label differs; no proposal from failed trace
        study,info=transform_traces(req)
        self.assertEqual(info['failed_train_traces_replayed_but_not_proposed'],1)
        self.assertEqual(study['train'][0]['output'],999)
    def test_failed_trace_correction_is_mandatory(self):
        req=request();req['train_episodes'][0]['accepted']=False
        with self.assertRaises(InvalidInput):transform_traces(req)
    def test_reject_caller_supplied_proposal(self):
        req=request();req['proposals']=[{'op':'const','value':5}]
        with self.assertRaises(InvalidInput):transform_traces(req)
    def test_reject_bad_promote_type(self):
        req=request();req['promote']='yes'
        with self.assertRaises(InvalidInput):transform_traces(req)
    def test_new_input_is_unseen_and_not_promoted_by_default(self):
        req=request();req.pop('promote')
        with tempfile.TemporaryDirectory() as td:
            service=Service(os.path.join(td,'test.sqlite3'))
            try:
                res=service.trace_study(req)
                self.assertEqual(res['status'],'locally_validated',res)
                self.assertNotIn('promotion',res)
                self.assertEqual(service.skill_list('trace_calc'),[])
            finally:service.registry.close()


class TestTraceIntegration(unittest.TestCase):
    def test_promote_and_predict_from_trace(self):
        with tempfile.TemporaryDirectory() as td:
            service=Service(os.path.join(td,'test.sqlite3'))
            try:
                res=service.trace_study(request())
                self.assertEqual(res['status'],'locally_validated',res)
                self.assertEqual(res['promotion']['status'],'active',res)
                value=service.skill_predict({'namespace':'trace_calc','inputs':{'a':13,'b':-9}})
                self.assertEqual(value['output'],8)
                self.assertTrue(service.skill_audit()['valid'])
            finally:service.registry.close()
    def test_cli_real_workflow(self):
        with tempfile.TemporaryDirectory() as td:
            requestfile=Path(td)/'trace.json'
            requestfile.write_text(json.dumps(request()),encoding='utf8')
            db=Path(td)/'skills.sqlite3'
            env={**os.environ,'PYTHONPATH':str(ROOT/'src')}
            call=subprocess.run([sys.executable,'-m','sis','--db',str(db),'trace-study',str(requestfile)],
                                capture_output=True,text=True,env=env)
            self.assertEqual(call.returncode,0,call.stderr)
            self.assertEqual(json.loads(call.stdout)['promotion']['status'],'active')
            query=Path(td)/'predict.json';query.write_text(json.dumps({'namespace':'trace_calc','inputs':{'a':15,'b':11}}))
            call=subprocess.run([sys.executable,'-m','sis','--db',str(db),'skill-predict',str(query)],
                                capture_output=True,text=True,env=env)
            self.assertEqual(call.returncode,0,call.stderr)
            self.assertEqual(json.loads(call.stdout)['output'],52)
    def test_ambiguous_traces_not_promoted(self):
        req=request()
        req['train_episodes']=[{'inputs':{'a':n,'b':n},'accepted':True,'observed_output':n,
                                'steps':[{'name':'x','expr':inp('a'),'value':n}]} for n in (1,3,5)]
        req['validation_episodes']=[{'inputs':{'a':n,'b':n},'accepted':True,'observed_output':n} for n in (7,9)]
        with tempfile.TemporaryDirectory() as td:
            service=Service(os.path.join(td,'s.sqlite3'))
            try:
                res=service.trace_study(req)
                self.assertEqual(res['status'],'ambiguous',res)
                self.assertEqual(res['promotion']['status'],'rejected')
                self.assertEqual(service.skill_list('trace_calc'),[])
            finally:service.registry.close()

if __name__=='__main__': unittest.main()
