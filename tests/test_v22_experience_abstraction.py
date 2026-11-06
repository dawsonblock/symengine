"""Independent targeted v2.2 replay/abstraction security and integration tests."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from sis.errors import InvalidInput
from sis.experience_events import InstrumentedSession, capture_plan, replay_capture
from sis.abstraction_engine import abstract_captures
from sis.service import Service
from sis.validation import digest


def capture(a=3,b=7, *, swapped=False):
    sess=InstrumentedSession({'a':a,'b':b})
    if swapped:
        interim=sess.call('sub',left=sess.input('a'),right=sess.input('b'),step_id='subtotal')
    else:
        interim=sess.call('add',left=sess.input('a'),right=sess.input('b'),step_id='subtotal')
    sess.call('mul',left=interim,right=sess.literal(2),step_id='doubled')
    return sess.capture()


def request():
    return {'namespace':'observed', 'promote':True,
            'train_captures':[{'capture':capture(a,b),'accepted':True}
                              for a,b in [(1,2),(5,-2),(-3,7),(11,13)]],
            'validation':[{'inputs':{'a':7,'b':8},'output':30},
                          {'inputs':{'a':-10,'b':6},'output':-8},
                          {'inputs':{'a':20,'b':0},'output':40}]}


class CaptureTests(unittest.TestCase):
    def test_repeatable_replay(self):
        rec=capture(5,-2)
        got=replay_capture(rec)
        self.assertEqual(got['observed_output'],6)
        self.assertEqual(got['events_replayed'],2)
        self.assertEqual(got['program']['op'],'let')
        self.assertEqual(got['steps'][1]['expr']['left'],{'op':'var','name':'subtotal'})

    def test_concrete_observation_infers_unique_sources(self):
        ses=InstrumentedSession({'a':5,'b':-2})
        first=ses.call('add',left=5,right=-2,step_id='total')
        ses.call('mul',left=first,right=ses.literal(2),step_id='twice')
        out=replay_capture(ses.capture())
        self.assertEqual(out['steps'][0]['expr']['left'],{'op':'input','name':'a'})
        self.assertEqual(out['steps'][0]['expr']['right'],{'op':'input','name':'b'})

    def test_concrete_ambiguous_values_are_rejected(self):
        ses=InstrumentedSession({'a':5,'b':5})
        with self.assertRaisesRegex(InvalidInput,'ambiguous provenance'):
            ses.call('add',left=5,right=5)
        self.assertEqual(len(ses.events),0)

    def test_explicit_ref_resolves_ambiguous_values(self):
        ses=InstrumentedSession({'a':5,'b':5})
        ses.call('add',left=ses.input('a'),right=ses.input('b'))
        self.assertEqual(replay_capture(ses.capture())['observed_output'],10)

    def test_previous_result_collision_rejected(self):
        ses=InstrumentedSession({'a':5,'b':3,'c':8})
        ses.call('add',left=ses.input('a'),right=ses.input('b'),step_id='total')
        # The intermediate result 8 collides with a separate input c=8.
        with self.assertRaisesRegex(InvalidInput,'ambiguous provenance'):
            ses.call('mul',left=8,right=ses.literal(2))

    def test_cross_session_ref(self):
        one=InstrumentedSession({'a':1})
        two=InstrumentedSession({'a':2})
        with self.assertRaises(InvalidInput):
            two.call('add',left=one.input('a'),right=two.literal(1))

    def test_unknown_tool(self):
        ses=InstrumentedSession({'a':1})
        with self.assertRaises(InvalidInput):
            ses.call('shell',left=ses.input('a'),right=ses.literal(1))

    def test_no_arbitrary_inputs(self):
        for invalid in ({'a':[1,2]},{'a':10**12},{'1x':7}):
            with self.subTest(invalid=invalid),self.assertRaises(InvalidInput):
                InstrumentedSession(invalid)

    def test_no_events(self):
        with self.assertRaises(InvalidInput): InstrumentedSession({'a':1}).capture()

    def test_bool_and_int_distinct(self):
        ses=InstrumentedSession({'x':True, 'y':2})
        self.assertEqual(ses.infer(1).reference, {'literal':1})
        with self.assertRaises(InvalidInput):
            ses.call('add',left=ses.input('x'),right=ses.input('y'))

    def test_tamper_result(self):
        rec=capture();rec['events'][0]['result']=999
        with self.assertRaises(InvalidInput): replay_capture(rec)

    def test_tamper_hash(self):
        rec=capture();rec['events'][0]['hash']='f'*64
        with self.assertRaises(InvalidInput): replay_capture(rec)

    def test_tamper_arguments_and_rehash_event_only(self):
        rec=capture();rec['events'][1]['resolved']['left']=42
        body={k:v for k,v in rec['events'][1].items() if k!='hash'}
        rec['events'][1]['hash']=digest(body)
        with self.assertRaises(InvalidInput): replay_capture(rec)

    def test_tamper_capture_output(self):
        rec=capture();rec['observed_output']=9
        with self.assertRaises(InvalidInput): replay_capture(rec)

    def test_tamper_capture_schema(self):
        rec=capture();rec['new_field']='no'
        with self.assertRaises(InvalidInput): replay_capture(rec)

    def test_no_forward_references(self):
        rec=capture()
        rec['events'][0]['bindings']['left']={'step':'doubled'}
        with self.assertRaises(InvalidInput): replay_capture(rec)

    def test_no_more_than_six(self):
        ses=InstrumentedSession({'a':2})
        x=ses.input('a')
        for i in range(6):
            x=ses.call('add',left=x,right=ses.literal(1),step_id=f's{i}')
        with self.assertRaises(InvalidInput):
            ses.call('add',left=x,right=ses.literal(1),step_id='s6')

    def test_plan_and_replay(self):
        plan={'inputs':{'a':15,'b':11}, 'calls':[
            {'id':'sum','tool':'add','left':{'input':'a'},'right':{'input':'b'}},
            {'id':'double','tool':'mul','left':{'step':'sum'},'right':{'literal':2}}]}
        rec=capture_plan(plan)
        self.assertEqual(replay_capture(rec)['observed_output'],52)

    def test_plan_bad_step_reference(self):
        plan={'inputs':{'a':1},'calls':[
            {'id':'out','tool':'add','left':{'step':'missing'},'right':{'literal':2}}]}
        with self.assertRaises(InvalidInput): capture_plan(plan)

    def test_strings_supported(self):
        ses=InstrumentedSession({'first':'AB','second':'cd'})
        ses.call('concat',left=ses.input('first'),right=ses.input('second'))
        self.assertEqual(replay_capture(ses.capture())['observed_output'],'ABcd')

    def test_metadata_does_not_claim_attestation(self):
        scope=capture()['evidence_scope']
        self.assertIn('no external attestation',scope)


class AbstractionTests(unittest.TestCase):
    def test_valid_abstraction(self):
        req, evidence=abstract_captures(request())
        self.assertEqual(evidence['distinct_successful_programs'],1)
        self.assertEqual(evidence['captures_replayed'],4)
        self.assertEqual(req['validation_episodes'][0]['observed_output'],30)
        self.assertNotIn('steps',req['validation_episodes'][0])

    def test_train_duplicate(self):
        req=request();req['train_captures'][1]['capture']=copy.deepcopy(req['train_captures'][0]['capture'])
        with self.assertRaisesRegex(InvalidInput,'duplicate training'):
            abstract_captures(req)

    def test_train_test_overlap(self):
        req=request();req['validation'][0]['inputs']={'a':1,'b':2}
        with self.assertRaisesRegex(InvalidInput,'overlaps'):
            abstract_captures(req)

    def test_mixed_programs_rejected(self):
        req=request();req['train_captures'][0]['capture']=capture(1,2,swapped=True)
        with self.assertRaisesRegex(InvalidInput,'disagree'):
            abstract_captures(req)

    def test_failed_needs_correction(self):
        req=request();req['train_captures'][0]['accepted']=False
        with self.assertRaises(InvalidInput): abstract_captures(req)

    def test_failed_not_proposed(self):
        req=request()
        req['train_captures'].append({'capture':capture(2,11,swapped=True),
                                      'accepted':False,'correct_output':26})
        _, evidence=abstract_captures(req)
        self.assertEqual(evidence['corrected_failures'],1)
        self.assertEqual(evidence['distinct_successful_programs'],1)

    def test_three_successful_required(self):
        req=request();req['train_captures']=req['train_captures'][:2]
        with self.assertRaises(InvalidInput): abstract_captures(req)

    def test_validation_cannot_supply_trace(self):
        req=request();req['validation'][0]['steps']=[]
        with self.assertRaises(InvalidInput): abstract_captures(req)

    def test_validation_type_is_enforced(self):
        req=request();req['validation'][0]['output']=True
        # The downstream governed study will reject differing output types.
        with tempfile.TemporaryDirectory() as path:
            svc=Service(str(Path(path)/'db.sqlite3'))
            try:
                with self.assertRaises(InvalidInput):svc.experience_induce(req)
            finally: svc.registry.close()

    def test_wrong_validation_blocks_promotion(self):
        req=request();req['validation'][0]['output']=999
        with tempfile.TemporaryDirectory() as path:
            svc=Service(str(Path(path)/'db.sqlite3'))
            try:
                value=svc.experience_induce(req)
                self.assertNotEqual(value['status'],'locally_validated')
                self.assertEqual(value['promotion']['status'],'rejected')
                self.assertEqual(svc.skill_list('observed'),[])
            finally: svc.registry.close()

    def test_end_to_end_skill_promotion(self):
        with tempfile.TemporaryDirectory() as path:
            svc=Service(str(Path(path)/'db.sqlite3'))
            try:
                result=svc.experience_induce(request())
                self.assertEqual(result['status'],'locally_validated')
                self.assertEqual(result['promotion']['status'],'active')
                pred=svc.skill_predict({'namespace':'observed','inputs':{'a':15,'b':11}})
                self.assertEqual(pred['output'],52)
                self.assertTrue(svc.skill_audit()['valid'])
            finally: svc.registry.close()

if __name__=='__main__': unittest.main()
