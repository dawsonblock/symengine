"""Adversarial regression tests for bounded AST code repair, v2.4."""
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from sis.errors import InvalidInput, RuleRejected
from sis.bridge import ToolBridge
from sis.service import Service
from sis.code_learning import capture_repair, replay_repair, check_cases, transform, preview_patch
from sis.validation import digest

RECIPE={'kind':'binary_operator_swap','from_op':'Sub','to_op':'Add'}


def program(function, a, b, *, operation='-', comment=''):
    return f'{comment}def {function}({a}, {b}):\n    return {a} {operation} {b}\n'


def cases(a,b, pairs=((2,3),(8,-2),(-3,7))):
    return [{'args':{a:x,b:y},'expected':x+y} for x,y in pairs]


def capture(fn,a,b,filename):
    return capture_repair({'source':program(fn,a,b),'filename':filename,'function':fn,
                           'recipe':RECIPE,'cases':cases(a,b)})


def study(promote=True):
    return {'namespace':'patch_test','promote':promote,
      'train_captures':[capture('add_two','a','b','a.py'),
                        capture('combine','x','y','b.py'),
                        capture('accumulate','lhs','rhs','c.py')],
      'validation':[{'source':program('merge','m','n'),'filename':'held_a.py',
                     'function':'merge','cases':cases('m','n')},
                    {'source':program('calc','left','right',comment='# internal\n'),
                     'filename':'held_b.py','function':'calc','cases':cases('left','right',((6,1),(2,8)))}]}


class CodeLearningTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.service=Service(str(Path(self.temp.name)/'records.sqlite3'))
    def tearDown(self):
        self.service.registry.close()
        self.temp.cleanup()

    def test_capture_observed_and_replay(self):
        c=capture('combine','x','y','a.py')
        self.assertEqual(c['before']['passed'],0)
        self.assertEqual(c['after']['passed'],3)
        replay=replay_repair(c)
        self.assertEqual(replay['recipe'],RECIPE)
        self.assertNotEqual(replay['source_digest'],replay['patched_digest'])

    def test_captured_source_is_never_executed(self):
        source="import subprocess\nsubprocess.run(['echo', 'never'])\ndef calc(a,b):\n    return a-b\n"
        with self.assertRaises(InvalidInput):
            capture_repair({'source':source,'filename':'safe.py','function':'calc','recipe':RECIPE,
                            'cases':cases('a','b')})

    def test_generalize_three_distinct_function_names(self):
        out=self.service.code_study(study())
        self.assertEqual(out['status'],'locally_validated')
        self.assertEqual(out['validation_passed'],2)
        rid=out['promotion']['recipe_id']
        self.assertEqual(self.service.code_audit()['status'],'valid')
        self.assertEqual(len(self.service.code_list('patch_test')),1)
        prediction=self.service.code_preview({'namespace':'patch_test','recipe_id':rid,
             'source':program('new_fn','f','g'),'filename':'new.py','function':'new_fn'})
        self.assertEqual(prediction['status'],'preview')
        self.assertIn('f + g',prediction['patched_source'])
        self.assertIn('-    return f - g',prediction['diff'])

    def test_requires_separate_holdout_and_does_not_promote_failed(self):
        req=study()
        req['validation'][1]['cases'][1]['expected']=99
        out=self.service.code_study(req)
        self.assertEqual(out['status'],'validation_failed')
        self.assertEqual(out['promotion']['status'],'rejected')
        self.assertEqual(self.service.code_list('patch_test'),[])

    def test_training_overlap_rejected(self):
        req=study()
        req['validation'][0]['source']=req['train_captures'][0]['source']
        req['validation'][0]['function']=req['train_captures'][0]['function']
        with self.assertRaises(InvalidInput):self.service.code_study(req)

    def test_forged_result_with_reforged_digest_rejected(self):
        rec=capture('calc','a','b','c.py')
        rec['after']['cases'][0]['actual']=999
        rec['capture_digest']=digest({k:v for k,v in rec.items() if k!='capture_digest'})
        with self.assertRaises(InvalidInput):replay_repair(rec)

    def test_accepted_capture_must_pass_all_labeled_test_vectors(self):
        rec=capture_repair({'source':program('calc','a','b'),'filename':'a.py','function':'calc','recipe':RECIPE,
                            'cases':[{'args':{'a':2,'b':3},'expected':5},
                                     {'args':{'a':8,'b':2},'expected':100}]})
        req=study();req['train_captures'][0]=rec
        with self.assertRaises(InvalidInput):self.service.code_study(req)

    def test_ambiguous_operator_rejected(self):
        source='def calc(a,b):\n    return (a-b)-(a-b)\n'
        with self.assertRaises(InvalidInput):transform(source,'calc',RECIPE)

    def test_no_source_operator_rejected(self):
        with self.assertRaises(InvalidInput):transform('def f(a,b):\n return a+b\n','f',RECIPE)

    def test_filename_escape_rejected(self):
        for filename in ('../a.py','a/b.py','.hidden.py','a.txt','/tmp/a.py','a\\b.py'):
            with self.subTest(filename=filename),self.assertRaises(InvalidInput):
                capture_repair({'source':program('calc','a','b'),'filename':filename,
                                'function':'calc','recipe':RECIPE,'cases':cases('a','b')})

    def test_unsafe_python_syntax_is_not_executed(self):
        for src in ('def calc(a,b):\n return eval("1")\n',
                    'def calc(a,b):\n return a[0]-b\n',
                    'def calc(a,b):\n import os\n return a-b\n'):
            with self.subTest(src=src),self.assertRaises(InvalidInput):
                check_cases(src,'calc',cases('a','b'))

    def test_boolean_rejected_as_integer(self):
        with self.assertRaises(InvalidInput):
            check_cases(program('calc','a','b'),'calc',[{'args':{'a':True,'b':1},'expected':2},
                                                      {'args':{'a':2,'b':2},'expected':4}])

    def test_zero_division_interpreted_as_failure(self):
        result=check_cases('def f(a,b):\n return a//b\n','f',
                           [{'args':{'a':2,'b':0},'expected':0},
                            {'args':{'a':4,'b':2},'expected':2}])
        self.assertEqual(result['passed'],1)
        self.assertIsNone(result['cases'][0]['actual'])

    def test_duplicate_vector_refused(self):
        with self.assertRaises(InvalidInput):
            check_cases(program('calc','a','b'),'calc',cases('a','b',((2,3),(2,3))))

    def test_unsupported_operation_refused(self):
        with self.assertRaises(InvalidInput):
            transform(program('calc','a','b'),'calc',{'kind':'run_shell','from_op':'Sub','to_op':'Add'})

    def test_already_correct_before_rejected(self):
        with self.assertRaises(InvalidInput):
            capture_repair({'source':program('calc','a','b',operation='+'),'filename':'c.py',
                            'function':'calc','recipe':{'kind':'binary_operator_swap','from_op':'Add','to_op':'Sub'},
                            'cases':cases('a','b')})

    def test_model_bridge_read_only(self):
        self.service.code_study(study())
        bridge=ToolBridge(self.service)
        allowed={spec['function']['name'] for spec in bridge.tools()}
        self.assertIn('sis_code_preview',allowed)
        self.assertNotIn('sis_code_study',allowed)
        self.assertNotIn('sis_code_retire',allowed)
        r=bridge.invoke('sis_code_preview',{'namespace':'patch_test','source':program('merge','x','y'),
                                            'filename':'n.py','function':'merge'})
        self.assertEqual(r['status'],'preview')
        for op in ('sis_code_study','sis_code_retire','shell','apply_patch'):
            with self.assertRaises(InvalidInput):bridge.invoke(op,{})

    def test_no_unique_recipe_abstain(self):
        r=self.service.code_preview({'namespace':'new','source':program('calc','a','b'),
                                     'filename':'x.py','function':'calc'})
        self.assertEqual(r['status'],'abstain')

    def test_registry_hash_corruption_abstains(self):
        self.service.code_study(study())
        self.service.registry.conn.execute("UPDATE sis_code_recipes SET recipe_json='{}'")
        self.service.registry.conn.commit()
        with self.assertRaises(RuleRejected):self.service.code_audit()
        result=self.service.code_preview({'namespace':'patch_test','source':program('calc','a','b'),
                                          'filename':'x.py','function':'calc'})
        self.assertEqual(result['status'],'abstain')

    def test_retire_and_no_silent_reactivation(self):
        request=study()
        rid=self.service.code_study(request)['promotion']['recipe_id']
        self.assertEqual(self.service.code_retire({'namespace':'patch_test','recipe_id':rid})['status'],'retired')
        self.assertEqual(self.service.code_audit()['status'],'valid')
        with self.assertRaises(RuleRejected):self.service.code_study(request)

    def test_reject_conflicting_recipe_in_namespace(self):
        self.service.code_study(study())
        # Swap from addition to subtraction on unrelated arithmetic task.
        inverse={'kind':'binary_operator_swap','from_op':'Add','to_op':'Sub'}
        def make(fn,a,b,filename):
            source=program(fn,a,b,operation='+')
            t=[{'args':{a:8,b:3},'expected':5},{'args':{a:2,b:4},'expected':-2}]
            return capture_repair({'source':source,'filename':filename,'function':fn,'recipe':inverse,'cases':t})
        req={'namespace':'patch_test','promote':True,
             'train_captures':[make('one','a','b','one.py'),make('two','x','y','two.py'),make('three','i','j','three.py')],
             'validation':[{'source':program('four','x','y',operation='+'),'filename':'four.py',
                           'function':'four','cases':[{'args':{'x':10,'y':3},'expected':7},
                                                     {'args':{'x':7,'y':4},'expected':3}]},
                           {'source':program('five','i','j',operation='+'),'filename':'five.py',
                           'function':'five','cases':[{'args':{'i':10,'j':2},'expected':8},
                                                     {'args':{'i':8,'j':1},'expected':7}]}]}
        with self.assertRaises(RuleRejected):self.service.code_study(req)

    def test_training_rejects_mixed_structures(self):
        req=study();req['train_captures'][2]=capture_repair({'source':program('accumulate','lhs','rhs',operation='+'),
            'filename':'c.py','function':'accumulate',
            'recipe':{'kind':'binary_operator_swap','from_op':'Add','to_op':'Sub'},
            'cases':[{'args':{'lhs':6,'rhs':1},'expected':5},{'args':{'lhs':10,'rhs':4},'expected':6}]})
        with self.assertRaises(InvalidInput):self.service.code_study(req)

    def test_no_unbounded_source(self):
        with self.assertRaises(InvalidInput):
            transform('# comment'*10000+program('f','a','b'),'f',RECIPE)

    def test_exact_replay_rejects_extra_fields(self):
        c=capture('calc','a','b','math.py');c['bogus']=True
        with self.assertRaises(InvalidInput):replay_repair(c)

    def test_preview_takes_no_filesystem_effects(self):
        before=set(Path(self.temp.name).iterdir())
        preview_patch({'source':program('f','a','b'),'filename':'x.py','function':'f'},RECIPE)
        after=set(Path(self.temp.name).iterdir())
        self.assertEqual(before,after)

if __name__=='__main__': unittest.main()
