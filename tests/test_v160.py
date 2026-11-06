"""Local functional and adversarial regression. Not independent evaluation evidence."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sis.errors import InvalidInput, RuleRejected
from sis.paired_eval import run_paired, exact_mcnemar_pvalue, _strict_answer
from sis.service import Service
from sis.validation import digest


def study():
    examples = lambda data: [{'inputs': {'a': x, 'b': y}, 'output': x+y} for x,y in data]
    return {'namespace': 'pairtest', 'train': examples([(1,4),(2,7),(-3,5),(5,-2),(0,8)]),
            'validation': examples([(4,9),(-4,-6),(11,3)]), 'promote': True}


def dataset(n=30):
    return {'task_id':'synthetic-paired-demo', 'namespace':'pairtest',
            'cases':[{'inputs':{'a':i+300,'b':-7}, 'output':i+293} for i in range(n)]}


class FakeClient:
    def __init__(self, kind='benefit'):
        self.kind = kind
        self.calls = []
        self.counter = 0

    def complete_with_metadata(self, messages, max_tokens=128):
        self.calls.append(copy.deepcopy(messages))
        data = json.loads(messages[-1]['content'])
        inp = data['task_inputs']
        expected = inp['a'] + inp['b']
        assisted = data.get('sis_read_only_prediction', {}).get('status') == 'predicted'
        if self.kind == 'error' and assisted:
            raise ConnectionError('simulated provider failure: secret not echoed')
        if self.kind == 'both_correct':
            predicted = expected
        elif self.kind == 'no_benefit':
            predicted = 0
        elif self.kind == 'sometimes_abstain' and not assisted:
            return '{"abstain":true,"answer":null}', {'prompt_tokens':10,'completion_tokens':3}
        else:
            predicted = expected if assisted else 0
        return json.dumps({'abstain':False,'answer':predicted}), {'prompt_tokens':10,'completion_tokens':5}


class TestPairedEvaluation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'rules.sqlite3'
        self.service = Service(self.path)
        promotion = self.service.study(study())
        self.assertEqual(promotion['promotion']['status'], 'active')

    def tearDown(self):
        self.service.registry.close()
        self.tmp.cleanup()

    def test_end_to_end_paired_benefit_and_no_registry_write(self):
        before = self.service.registry.verify_audit()['events_verified']
        client = FakeClient()
        result = run_paired(dataset(), client, self.service, model_label='synthetic-only')
        self.assertEqual(result['status'], 'evaluated')
        self.assertEqual(result['qualification'], 'descriptive_paired_result_only')
        self.assertEqual(result['arms']['baseline']['correct'], 0)
        self.assertEqual(result['arms']['augmented']['correct'], 30)
        self.assertEqual(result['paired']['augmented_only_correct'], 30)
        self.assertEqual(result['paired']['baseline_only_correct'], 0)
        self.assertLess(result['paired']['mcnemar_exact_two_sided_p'], 0.001)
        self.assertEqual(result['sis_coverage'], 1.0)
        self.assertEqual(result['arms']['baseline']['reported_prompt_tokens'], 300)
        self.assertEqual(len(client.calls), 60)
        self.assertEqual(result['outcomes'][0]['request_order'], ['baseline','augmented'])
        self.assertEqual(result['outcomes'][1]['request_order'], ['augmented','baseline'])
        self.assertEqual(before, self.service.registry.verify_audit()['events_verified'])
        for messages in client.calls:
            sent = json.loads(messages[-1]['content'])
            self.assertNotIn('output', sent)
            self.assertNotIn('expected', sent)
            self.assertNotIn('answer_keys', sent)
            self.assertNotIn('cases', sent)
        self.assertNotIn('output', json.dumps(result['outcomes']))

    def test_both_correct_no_difference(self):
        result = run_paired(dataset(4), FakeClient('both_correct'), self.service)
        self.assertEqual(result['paired']['mcnemar_exact_two_sided_p'], 1.0)
        self.assertEqual(result['qualification'], 'not_qualified_small_sample')
        self.assertEqual(result['paired']['both_correct'], 4)

    def test_provider_error_invalidates_run(self):
        result = run_paired(dataset(3), FakeClient('error'), self.service)
        self.assertEqual(result['status'], 'invalid_due_to_provider_errors')
        self.assertEqual(result['qualification'], 'not_qualified_provider_errors')
        self.assertEqual(result['arms']['augmented']['model_errors'], 3)

    def test_regression_no_sis_prediction(self):
        d = dataset(2); d['namespace']='no_rules'
        res=run_paired(d, FakeClient(), self.service)
        self.assertEqual(res['sis_coverage'],0)
        self.assertEqual(res['arms']['augmented']['correct'],0)

    def test_new_dataset_rejects_duplicate_cases(self):
        d=dataset(3);d['cases'][2]=copy.deepcopy(d['cases'][1])
        with self.assertRaisesRegex(InvalidInput, 'duplicate'):
            run_paired(d, FakeClient(), self.service)

    def test_pinned_unknown_rule_rejected(self):
        d=dataset(2);d['rule_id']='wrong'
        with self.assertRaisesRegex(InvalidInput, 'pinned'):
            run_paired(d, FakeClient(), self.service)

    def test_invalid_types_rejected(self):
        for value in (1.0, True, None, {}, ['x']):
            d=dataset(2);d['max_tokens']=value
            with self.assertRaises(InvalidInput):
                run_paired(d, FakeClient(), self.service)

    def test_dataset_unknown_keys_rejected(self):
        d=dataset(2);d['hidden_label_instructions']='ignore'
        with self.assertRaises(InvalidInput):
            run_paired(d, FakeClient(), self.service)

    def test_registry_drift_rejected(self):
        client=FakeClient()
        original=client.complete_with_metadata
        count=[0]
        def corrupt(messages,max_tokens=128):
            count[0]+=1
            if count[0]==2:
                self.service.registry.conn.execute('UPDATE rules SET status="suspended"')
                self.service.registry.conn.commit()
            return original(messages,max_tokens=max_tokens)
        client.complete_with_metadata=corrupt
        with self.assertRaises((InvalidInput, RuleRejected)):
            run_paired(dataset(3), client, self.service)

    def test_preexisting_bad_audit_rejected(self):
        self.service.registry.conn.execute('DELETE FROM audit')
        self.service.registry.conn.commit()
        with self.assertRaises(InvalidInput):
            run_paired(dataset(2), FakeClient(), self.service)

    def test_output_strictness(self):
        invalid=['42', '{"answer":true,"abstain":false}',
                 '{"answer":42.0,"abstain":false}',
                 '{"answer":42,"abstain":false,"extra":5}',
                 '{"answer":42,"abstain":true}',
                 '```json\n{"abstain":false,"answer":42}\n```', '{}', 'null']
        for content in invalid:
            self.assertEqual(_strict_answer(content,int)[0], 'invalid_output')
        self.assertEqual(_strict_answer('{"abstain":false,"answer":42}',int),('answered',42))
        self.assertEqual(_strict_answer('{"abstain":true,"answer":null}',int),('abstain',None))

    def test_exact_mcnemar(self):
        self.assertEqual(exact_mcnemar_pvalue(0,0), 1)
        self.assertEqual(exact_mcnemar_pvalue(0,1), 1)
        self.assertEqual(exact_mcnemar_pvalue(0,5), 0.0625)
        self.assertEqual(exact_mcnemar_pvalue(3,3), 1)
        with self.assertRaises(InvalidInput):
            exact_mcnemar_pvalue(True,0)

    def test_cli_requires_opt_in(self):
        d=Path(self.tmp.name)/'data.json'
        d.write_text(json.dumps(dataset(3)))
        out=Path(self.tmp.name)/'result.json'
        env={**os.environ, 'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src'),
             'SIS_ENABLE_LLM':'0'}
        cmd=[sys.executable,'-m','sis','--db',str(self.path),'paired-eval',str(d),str(out)]
        failure=subprocess.run(cmd,env=env,text=True,capture_output=True,timeout=10)
        self.assertEqual(failure.returncode,2)
        self.assertIn('BOTH --allow-network',failure.stderr)
        self.assertFalse(out.exists())

    def test_real_http_adapter_cli_loopback_mock(self):
        # Exercises actual CLI -> CompatibleLLM -> HTTP JSON -> paired scorer,
        # but the server is an in-process STUB and is not a real LLM.
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from threading import Thread
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                size = int(self.headers.get('Content-Length', '0'))
                obj = json.loads(self.rfile.read(size))
                requests.append(obj)
                task = json.loads(obj['messages'][-1]['content'])
                inputs = task['task_inputs']
                result = inputs['a']+inputs['b'] if task.get('sis_read_only_prediction', {}).get('status') == 'predicted' else -1
                payload = json.dumps({'choices': [{'message': {'content': json.dumps({'abstain': False, 'answer': result})}}],
                    'usage': {'prompt_tokens': 17, 'completion_tokens': 5}}).encode()
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker = Thread(target=srv.serve_forever,daemon=True)
        worker.start()
        try:
            data=Path(self.tmp.name)/'data.json'
            data.write_text(json.dumps(dataset(2)))
            out=Path(self.tmp.name)/'out.json'
            env={**os.environ, 'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src'),
                 'SIS_ENABLE_LLM':'1', 'SIS_LLM_URL': f'http://127.0.0.1:{srv.server_address[1]}/v1/chat/completions',
                 'SIS_LLM_MODEL':'STUB_NOT_REAL', 'SIS_LLM_API_KEY':''}
            cmd=[sys.executable,'-m','sis','--db',str(self.path),'paired-eval',str(data),str(out),'--allow-network']
            run = subprocess.run(cmd,env=env,text=True,capture_output=True,timeout=20)
            self.assertEqual(run.returncode,0,run.stderr)
            report=json.loads(out.read_text())
            self.assertEqual(len(requests),4)
            self.assertEqual(report['paired']['augmented_only_correct'],2)
            self.assertEqual(report['arms']['baseline']['reported_prompt_tokens'],34)
            self.assertEqual(report['model'],'STUB_NOT_REAL')
            second=subprocess.run(cmd,env=env,text=True,capture_output=True,timeout=20)
            self.assertEqual(second.returncode,2)
            self.assertEqual(len(requests),4, 'existing output must prevent remote requests')
        finally:
            srv.shutdown()
            srv.server_close()
            worker.join(timeout=5)

    def test_raw_reference_labels_never_returned(self):
        response=run_paired(dataset(2),FakeClient(),self.service)
        self.assertNotIn('expected_output',response['outcomes'][0])
        self.assertNotIn('output',response['outcomes'][0])
        self.assertEqual(response['case_digest'],digest(dataset(2)['cases']))


if __name__=='__main__':
    unittest.main()
