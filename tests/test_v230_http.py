"""v2.3 HTTP authorization regression: observer key cannot promote workflows."""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


class WorkflowHttpTests(unittest.TestCase):
    def test_admin_separation_and_read_only_inference(self):
        with tempfile.TemporaryDirectory() as td:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            env = dict(os.environ)
            env['SIS_API_KEY']='reader-example-password-only'
            env['SIS_ADMIN_KEY']='operator-separate-password-long-value'
            root=Path(__file__).resolve().parents[1]
            env['PYTHONPATH']=str(root/'src')
            proc=subprocess.Popen([sys.executable,'-m','sis','--db',str(Path(td)/'db.sqlite3'),
                                   'serve','--host','127.0.0.1','--port',str(port)],
                                  env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(50):
                    try:
                        con=http.client.HTTPConnection('127.0.0.1',port,timeout=2)
                        con.request('GET','/health')
                        result=con.getresponse();result.read();con.close()
                        break
                    except OSError:
                        if proc.poll() is not None:
                            self.fail('HTTP child terminated before ready')
                        time.sleep(.05)
                else: self.fail('HTTP server did not start')
                training=json.loads((root/'examples'/'v2_3'/'workflow_study.json').read_text())
                sample=json.loads((root/'examples'/'v2_3'/'workflow_predict.json').read_text())
                def send(path,body,admin=False):
                    c=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
                    head={'Content-Type':'application/json','X-SIS-Key':env['SIS_API_KEY']}
                    if admin: head['X-SIS-Admin-Key']=env['SIS_ADMIN_KEY']
                    c.request('POST',path,json.dumps(body),headers=head)
                    res=c.getresponse()
                    result=res.status,json.loads(res.read())
                    c.close()
                    return result
                status,body=send('/v1/workflows/study',training)
                self.assertEqual(status,403)
                status,body=send('/v1/workflows/study',training,admin=True)
                self.assertEqual(status,200)
                self.assertEqual(body['promotion']['status'],'active')
                status,body=send('/v1/workflows/predict',sample)
                self.assertEqual(status,200)
                self.assertEqual(body['output'],26)
                status,body=send('/v1/workflows/retire',{'namespace':'tabular_demo','workflow_id':body['workflow_id']})
                self.assertEqual(status,403)
            finally:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill();proc.wait(timeout=3)


if __name__=='__main__': unittest.main()
