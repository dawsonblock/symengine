"""v1.7 procedural engine and governed skill catalog regression tests."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from sis.errors import InvalidInput, RuleRejected
from sis.service import Service
from sis.bridge import ToolBridge
from sis.skill_learning import study
from sis.skill_program import execute, validate_program

ROOT = Path(__file__).resolve().parents[1]

def c(x):return {'op':'const','value':x}
def i(name):return {'op':'input','name':name}
def b(fn,l,r):return {'op':'binary','fn':fn,'left':l,'right':r}
def sum_case(vals):return {'inputs':{'nums':vals},'output':sum(vals)}

def sum_study():
    return {'namespace':'list_sum', 'train':[sum_case(x) for x in ([1,2,3],[2,7,1],[-2,4,8],[7,8,-4])],
            'validation':[sum_case([11,2,7]),sum_case([-9,3,1])], 'promote':True}

class InterpreterTests(unittest.TestCase):
    def test_let_and_conditional_branch(self):
        prog={'op':'let','name':'total','value':b('add',i('a'),i('b')),
              'body':{'op':'if','condition':b('gt',{'op':'var','name':'total'},c(0)),
              'then':{'op':'var','name':'total'},'else':c(0)}}
        self.assertEqual(execute(prog,{'a':1,'b':-6}),0)
        self.assertEqual(execute(prog,{'a':6,'b':3}),9)
    def test_bounded_fold(self):
        prog={'op':'fold','field':'nums','item':'each','acc':'total','initial':c(0),
              'body':b('add',{'op':'var','name':'total'},{'op':'var','name':'each'})}
        self.assertEqual(execute(prog,{'nums':[1,2,3,4]}),10)
        with self.assertRaises(InvalidInput):execute(prog,{'nums':list(range(17))})
    def test_bad_ast_and_bad_symbols(self):
        invalid=[{'op':'python','code':'print(1)'}, {'op':'var','name':'missing'},
                 {'op':'input','name':'__class__','extra':1},
                 {'op':'fold','field':'nums','item':'x','acc':'x','initial':c(0),'body':c(2)},
                 {'op':'call','skill_id':'not-a-sha','args':{'x':i('x')}}]
        for ast in invalid:
            with self.subTest(ast=ast), self.assertRaises(InvalidInput):validate_program(ast,schema={'nums':['int'],'x':'int'})
    def test_overflow_type_and_short_circuit_branch(self):
        with self.assertRaises(InvalidInput):execute(b('mul',c(1000000000),c(1000000000)),{'x':0})
        with self.assertRaises(InvalidInput):execute(b('add',c(True),c(3)),{'x':0})
        program={'op':'if','condition':c(True),'then':c(123),
                 'else':b('mul',c(1000000000),c(1000000000))}
        self.assertEqual(execute(program,{'x':0}),123)
    def test_depth_and_fuel_limits(self):
        tree=i('n')
        for _ in range(13):tree={'op':'unary','fn':'abs','arg':tree}
        with self.assertRaises(InvalidInput):validate_program(tree,schema={'n':'int'})
        # Nested folds are explicitly capped at 2 levels.
        tree={'op':'fold','field':'nums','item':'x0','acc':'a0','initial':c(0),'body':c(1)}
        for k in (1,2):
            tree={'op':'fold','field':'nums','item':'x'+str(k),'acc':'a'+str(k),'initial':c(0),'body':tree}
        with self.assertRaises(InvalidInput):validate_program(tree,schema={'nums':['int']})

class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory();self.db=os.path.join(self.dir.name,'catalog.db')
        self.s=Service(self.db)
    def tearDown(self):
        self.s.registry.close();self.dir.cleanup()
    def promote_sum(self):
        result=self.s.skill_study(sum_study())
        self.assertEqual(result['status'],'locally_validated',result)
        self.assertEqual(result['promotion']['status'],'active')
        return result['promotion']['id']
    def test_discover_promote_execute_and_reopen(self):
        sid=self.promote_sum()
        self.assertTrue(self.s.skill_audit()['valid'])
        self.assertEqual(self.s.skill_predict({'namespace':'list_sum','inputs':{'nums':[12,0,-3]}})['output'],9)
        self.s.registry.close()
        self.s=Service(self.db)
        self.assertEqual(self.s.skill_predict({'namespace':'list_sum','skill_id':sid,'inputs':{'nums':[2,2,2]}})['output'],6)
    def test_unsupported_and_abstain(self):
        self.promote_sum()
        self.assertEqual(self.s.skill_predict({'namespace':'list_sum','inputs':{'nums':[2,3]}})['status'],'abstain')
        self.assertEqual(self.s.skill_predict({'namespace':'missing','inputs':{'nums':[1,1,1]}})['status'],'abstain')
    def test_read_only_agent_bridge(self):
        self.promote_sum()
        bridge=ToolBridge(self.s)
        self.assertIn('sis_skill_predict',[x['function']['name'] for x in bridge.tools()])
        self.assertEqual(bridge.invoke('sis_skill_predict',json.dumps({'namespace':'list_sum','inputs':{'nums':[1,1,1]}}))['output'],3)
        with self.assertRaises(InvalidInput):bridge.invoke('sis_skill_study',{'promote':True})
        with self.assertRaises(InvalidInput):bridge.invoke('sis_skill_predict',{'inputs':{'nums':[1]},'promote':True})
    def test_duplicate_and_feedback_suspends(self):
        sid=self.promote_sum()
        second=self.s.skill_study(sum_study())
        self.assertEqual(second['promotion']['status'],'already_exists')
        self.assertTrue(self.s.skill_feedback({'namespace':'list_sum','skill_id':sid,'inputs':{'nums':[2,3,4]},'observed_output':9})['matched'])
        self.assertFalse(self.s.skill_feedback({'namespace':'list_sum','skill_id':sid,'inputs':{'nums':[2,3,4]},'observed_output':999})['matched'])
        self.assertTrue(self.s.skill_audit()['valid'])
        self.assertEqual(self.s.skill_predict({'namespace':'list_sum','inputs':{'nums':[1,2,3]}})['status'],'abstain')
        self.assertEqual(self.s.skill_retire({'namespace':'list_sum','skill_id':sid})['status'],'retired')
        self.assertTrue(self.s.skill_audit()['valid'])
    def test_feedback_type_mismatch(self):
        sid=self.promote_sum()
        with self.assertRaises(InvalidInput):
            self.s.skill_feedback({'namespace':'list_sum','skill_id':sid,'inputs':{'nums':[1,2,3]},'observed_output':True})
        self.assertTrue(self.s.skill_audit()['valid'])
    def test_in_db_tamper_rejected(self):
        self.promote_sum()
        with self.s.registry.conn:
            self.s.registry.conn.execute("UPDATE sis_skills SET status='retired'")
        self.assertFalse(self.s.skill_audit()['valid'])
        self.assertEqual(self.s.skill_predict({'namespace':'list_sum','inputs':{'nums':[1,2,3]}})['status'],'abstain')
        with self.assertRaises(RuleRejected):self.s.skill_list('list_sum')
    def test_mutation_of_audit_rejected(self):
        self.promote_sum()
        with self.s.registry.conn:
            self.s.registry.conn.execute("UPDATE sis_skill_events SET event='{}' WHERE seq=1")
        self.assertFalse(self.s.skill_audit()['valid'])
    def test_no_validation_overlap(self):
        req=sum_study();req['validation'][0]=copy.deepcopy(req['train'][0])
        with self.assertRaises(InvalidInput):self.s.skill_study(req)
    def test_no_promotion_on_ambiguity(self):
        # All train outputs equal x and y; several interpretations disagree elsewhere.
        req={'namespace':'amb','train':[{'inputs':{'x':n,'y':n},'output':n} for n in [1,3,7]],
             'validation':[{'inputs':{'x':n,'y':n},'output':n} for n in [9,11]],'promote':True}
        res=self.s.skill_study(req)
        self.assertEqual(res['status'],'ambiguous')
        self.assertEqual(res['promotion']['status'],'rejected')
    def test_benchmark_is_nonpromoting(self):
        self.promote_sum()
        res=self.s.skill_benchmark({'namespace':'list_sum','cases':[sum_case([1,1,1]),sum_case([2,3,4])]})
        self.assertEqual((res['predicted'],res['correct']),(2,2))
        self.assertEqual(self.s.skill_audit()['events_verified'],1)
    def test_nested_skill_calls_and_dependency_retirement(self):
        train=[{'inputs':{'a':a,'b':b},'output':a+b} for a,b in [(1,2),(2,4),(-3,5),(7,1)]]
        valid=[{'inputs':{'a':a,'b':b},'output':a+b} for a,b in [(10,5),(-2,-4)]]
        base=self.s.skill_study({'namespace':'compose','train':train,'validation':valid,'promote':True})
        self.assertEqual(base['status'],'locally_validated',base)
        sid=base['promotion']['id']
        call={'op':'call','skill_id':sid,'args':{'a':i('x'),'b':i('y')}}
        composite=b('add',call,c(1))
        req={'namespace':'compose','train':[{'inputs':{'x':a,'y':bb},'output':a+bb+1} for a,bb in [(1,2),(2,4),(-3,5),(7,1)]],
             'validation':[{'inputs':{'x':a,'y':bb},'output':a+bb+1} for a,bb in [(10,5),(-2,-4)]],
             'proposals':[composite],'promote':True}
        res=self.s.skill_study(req)
        self.assertEqual(res['status'],'locally_validated',res)
        composed_id=res['promotion']['id']
        self.assertEqual(self.s.skill_predict({'namespace':'compose','skill_id':composed_id,'inputs':{'x':8,'y':3}})['output'],12)
        self.s.skill_retire({'namespace':'compose','skill_id':sid})
        self.assertEqual(self.s.skill_predict({'namespace':'compose','skill_id':composed_id,'inputs':{'x':8,'y':3}})['status'],'abstain')
    def test_unauthorized_or_missing_dependency_fails(self):
        sid='a'*64
        call={'op':'call','skill_id':sid,'args':{'v':i('v')}}
        with self.assertRaises(InvalidInput):execute(call,{'v':2})
    def test_cli_smoke(self):
        request=os.path.join(self.dir.name,'study.json')
        Path(request).write_text(json.dumps(sum_study()))
        env={**os.environ,'PYTHONPATH':str(ROOT/'src')}
        r=subprocess.run([sys.executable,'-m','sis','--db',self.db,'skill-study',request],env=env,capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)['promotion']['status'],'active')
        r=subprocess.run([sys.executable,'-m','sis','--db',self.db,'skill-audit'],env=env,capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertTrue(json.loads(r.stdout)['valid'])

if __name__=='__main__':unittest.main()

class ExperienceTests(unittest.TestCase):
    def test_failed_episode_requires_external_correction(self):
        from sis.experience import transform_episodes
        req={'train_episodes':[{'inputs':{'n':k},'observed_output':k,'accepted':True} for k in [1,2,3]],
             'validation_episodes':[{'inputs':{'n':4},'observed_output':0,'accepted':False}]}
        with self.assertRaises(InvalidInput):transform_episodes(req)
        req['validation_episodes'][0]['correct_output']=4
        req['validation_episodes'].append({'inputs':{'n':5},'observed_output':5,'accepted':True})
        norm, meta=transform_episodes(req)
        self.assertEqual(norm['validation'][0]['output'],4)
        self.assertEqual(meta['corrected_failures'],1)
    def test_bad_trace_rejected(self):
        from sis.experience import transform_episodes
        req={'train_episodes':[{'inputs':{'n':k},'observed_output':k,'accepted':True,'trace':['A'*129]} for k in [1,2,3]],
             'validation_episodes':[{'inputs':{'n':n},'observed_output':n,'accepted':True} for n in [4,5]]}
        with self.assertRaises(InvalidInput):transform_episodes(req)
    def test_experience_study_no_fake_failed_truth(self):
        with tempfile.TemporaryDirectory() as td:
            service=Service(os.path.join(td,'test.sqlite3'))
            try:
                req={'namespace':'experience','promote':True,
                     'train_episodes':[{'inputs':{'n':n},'observed_output':n,'accepted':True,'trace':['observation']} for n in [-2,1,3]],
                     'validation_episodes':[{'inputs':{'n':n},'observed_output':0,'accepted':False,'correct_output':n} for n in [4,-5]]}
                result=service.experience_study(req)
                self.assertEqual(result['status'],'locally_validated')
                self.assertEqual(result['experience']['corrected_failures'],2)
                self.assertEqual(result['promotion']['status'],'active')
            finally:service.registry.close()
