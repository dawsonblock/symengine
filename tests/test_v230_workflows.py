"""v2.3 workflow security, canonical equivalence and persistent integration."""
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sis.errors import InvalidInput, RuleRejected
from sis.service import Service
from sis.workflow_engine import WorkflowSession, capture_plan, replay_capture, execute_plan, normalize_plan


def dataset(a,b,group='A'):
    return {'rows':[{'group':group,'amount':a},{'group':'B','amount':100},{'group':group,'amount':b}]}


def events(a,b,*, reversed_order=False, redundant=False):
    data=dataset(a,b)
    sess=WorkflowSession(data)
    if reversed_order:
        sess.call({'op':'filter_gt','field':'amount','value':-1000})
        sess.call({'op':'filter_eq','field':'group','value':'A'})
    else:
        sess.call({'op':'filter_eq','field':'group','value':'A'})
        sess.call({'op':'filter_gt','field':'amount','value':-1000})
    if redundant:
        sess.call({'op':'filter_eq','field':'group','value':'A'})
    sess.call({'op':'sum','field':'amount'})
    return sess.capture()


def study():
    return {'namespace':'tabular','promote':True,
      'train_captures':[{'capture':events(2,3), 'accepted':True,'expected_output':5},
                        {'capture':events(4,7,reversed_order=True), 'accepted':True,'expected_output':11},
                        {'capture':events(10,-5,redundant=True), 'accepted':True,'expected_output':5}],
      'validation':[{'data':dataset(8,12),'expected_output':20},
                    {'data':dataset(22,-7),'expected_output':15}]}


class WorkflowTests(unittest.TestCase):
    def test_replay_and_operation_provenance(self):
        rec=events(3,9)
        result=replay_capture(rec)
        self.assertEqual(result['output'],12)
        self.assertEqual(len(rec['events']),3)
        self.assertEqual(rec['events'][0]['observed']['matching_rows'],2)
        self.assertEqual(len(result['normalized_plan']),3)

    def test_equivalent_order_and_redundant_filter(self):
        a=replay_capture(events(4,6))
        b=replay_capture(events(4,6,reversed_order=True))
        c=replay_capture(events(4,6,redundant=True))
        self.assertEqual(a['fingerprint'],b['fingerprint'])
        self.assertEqual(a['fingerprint'],c['fingerprint'])
        self.assertEqual(execute_plan(a['data'],a['normalized_plan']),10)

    def test_noncommuting_aggs_are_rejected(self):
        data=dataset(1,2)
        with self.assertRaises(InvalidInput):
            capture_plan({'data':data,'plan':[{'op':'count'},{'op':'sum','field':'amount'}]})

    def test_shell_never_available(self):
        with self.assertRaises(InvalidInput):
            capture_plan({'data':dataset(1,2),'plan':[{'op':'shell','field':'amount'}]})

    def test_type_sensitive_columns_and_count(self):
        self.assertEqual(execute_plan({'rows':[{'x':True},{'x':False}]},[{'op':'distinct_count','field':'x'}]),2)
        self.assertEqual(execute_plan(dataset(10,2),[{'op':'filter_eq','field':'group','value':'Z'},{'op':'count'}]),0)
        with self.assertRaises(InvalidInput):
            execute_plan({'rows':[{'x':1},{'x':True}]},[{'op':'count'}])

    def test_overflow_rejected(self):
        with self.assertRaises(InvalidInput):
            execute_plan({'rows':[{'x':10**9},{'x':10**9}]},[{'op':'sum','field':'x'}])

    def test_tamper_intermediate_even_with_rehash(self):
        rec=events(3,9)
        rec['events'][0]['observed']['matching_rows']=3
        from sis.validation import digest
        for index,item in enumerate(rec['events']):
            item['prior']='0'*64 if index==0 else rec['events'][index-1]['hash']
            item['hash']=digest({k:v for k,v in item.items() if k!='hash'})
        rec['head']=rec['events'][-1]['hash']
        rec['capture_digest']=digest({k:v for k,v in rec.items() if k not in ('capture_digest','evidence_scope')})
        with self.assertRaises(InvalidInput):
            replay_capture(rec)

    def test_non_promoted_study_and_promotion(self):
        with tempfile.TemporaryDirectory() as td:
            svc=Service(str(Path(td)/'db.sqlite'))
            req=study();req['promote']=False
            result=svc.workflow_study(req)
            self.assertEqual(result['status'],'locally_validated')
            self.assertEqual(len(svc.workflow_list('tabular')),0)
            req['promote']=True
            result=svc.workflow_study(req)
            self.assertEqual(result['promotion']['status'],'active')
            pred=svc.workflow_predict({'namespace':'tabular','data':dataset(13,17)})
            self.assertEqual(pred['output'],30)
            self.assertEqual(svc.workflow_audit()['status'],'valid')
            self.assertEqual(len(svc.workflow_list('tabular')),1)
            again=svc.workflow_study(req)
            self.assertEqual(again['promotion']['status'],'already_active')
            svc.registry.close()

    def test_failed_holdout_not_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            svc=Service(str(Path(td)/'db.sqlite'))
            req=study()
            req['validation'][1]['expected_output']=999
            result=svc.workflow_study(req)
            self.assertEqual(result['status'],'validation_failed')
            self.assertEqual(result['promotion']['status'],'rejected')
            self.assertEqual(svc.workflow_list('tabular'),[])
            svc.registry.close()

    def test_train_test_overlap_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            svc=Service(str(Path(td)/'db.sqlite'))
            req=study()
            req['validation'][0]['data']=dataset(2,3)
            with self.assertRaises(InvalidInput): svc.workflow_study(req)
            svc.registry.close()

    def test_forged_success_label_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            svc=Service(str(Path(td)/'db.sqlite'))
            req=study();req['train_captures'][0]['expected_output']=0
            with self.assertRaises(InvalidInput): svc.workflow_study(req)
            svc.registry.close()

    def test_different_program_not_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            svc=Service(str(Path(td)/'db.sqlite'))
            req=study()
            wrong=capture_plan({'data':dataset(10,-5),'plan':[{'op':'filter_eq','field':'group','value':'A'},{'op':'count'}]})
            req['train_captures'][2]['capture']=wrong
            req['train_captures'][2]['expected_output']=2
            with self.assertRaises(InvalidInput): svc.workflow_study(req)
            svc.registry.close()

    def test_database_tamper_abstains_and_audit_fails(self):
        with tempfile.TemporaryDirectory() as td:
            db=str(Path(td)/'db.sqlite')
            svc=Service(db)
            result=svc.workflow_study(study())
            self.assertEqual(result['promotion']['status'],'active')
            svc.registry.conn.execute("UPDATE sis_tabular_workflows SET plan_json=?", ('[]',))
            svc.registry.conn.commit()
            pred=svc.workflow_predict({'namespace':'tabular','data':dataset(4,6)})
            self.assertEqual(pred['status'],'abstain')
            with self.assertRaises(RuleRejected): svc.workflow_audit()
            svc.registry.close()

    def test_retirement_works_and_prevents_reactivation(self):
        with tempfile.TemporaryDirectory() as td:
            svc=Service(str(Path(td)/'db.sqlite'))
            res=svc.workflow_study(study())
            wid=res['promotion']['workflow_id']
            svc.workflow_retire({'namespace':'tabular','workflow_id':wid})
            self.assertEqual(svc.workflow_predict({'namespace':'tabular','data':dataset(4,6)})['status'],'abstain')
            with self.assertRaises(RuleRejected): svc.workflow_study(study())
            self.assertEqual(svc.workflow_audit()['status'],'valid')
            svc.registry.close()

    def test_read_only_llm_bridge(self):
        from sis.bridge import ToolBridge
        with tempfile.TemporaryDirectory() as td:
            svc=Service(str(Path(td)/'db.sqlite'))
            bridge=ToolBridge(svc)
            self.assertEqual(bridge.invoke('sis_workflow_predict',{'namespace':'tabular','data':dataset(4,6)})['status'],'abstain')
            with self.assertRaises(InvalidInput): bridge.invoke('sis_workflow_study',study())
            svc.registry.close()


if __name__=='__main__': unittest.main()
