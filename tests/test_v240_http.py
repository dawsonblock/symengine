"""Protect code recipe promotion from read-only HTTP and model clients."""
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

from sis.code_learning import capture_repair

RECIPE={'kind':'binary_operator_swap','from_op':'Sub','to_op':'Add'}

def case(fn,a,b,fnm):
    return {'source':f'def {fn}({a},{b}):\n return {a}-{b}\n', 'filename':fnm,'function':fn,
            'cases':[{'args':{a:x,b:y},'expected':x+y} for x,y in ((2,3),(4,1))]}

class CodeHttpTests(unittest.TestCase):
    def test_separation_for_code_study_and_retirement(self):
        with tempfile.TemporaryDirectory() as temp:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            root=Path(__file__).resolve().parents[1]
            env={**os.environ,'PYTHONPATH':str(root/'src'),
                 'SIS_API_KEY':'readonly-model-token-example',
                 'SIS_ADMIN_KEY':'separate-operator-token-example-long'}
            proc=subprocess.Popen([sys.executable,'-m','sis','--db',str(Path(temp)/'db.sqlite3'),
                                   'serve','--host','127.0.0.1','--port',str(port)],
                                  cwd=root,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(80):
                    if proc.poll() is not None: self.fail('SIS server terminated')
                    try:
                        c=http.client.HTTPConnection('127.0.0.1',port,timeout=1)
                        c.request('GET','/health',headers={'X-SIS-Key':env['SIS_API_KEY']})
                        status=c.getresponse();status.read();c.close()
                        break
                    except OSError: time.sleep(.05)
                else:self.fail('SIS HTTP server did not start')
                def send(endpoint,request,admin=False):
                    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=6)
                    headers={'Content-Type':'application/json','X-SIS-Key':env['SIS_API_KEY']}
                    if admin:headers['X-SIS-Admin-Key']=env['SIS_ADMIN_KEY']
                    conn.request('POST',endpoint,json.dumps(request),headers=headers)
                    resp=conn.getresponse()
                    result=resp.status,json.loads(resp.read())
                    conn.close()
                    return result
                train=[case('first','a','b','a.py'),case('second','x','y','b.py'),case('third','u','v','c.py')]
                req={'namespace':'code_http','promote':True,
                     'train_captures':[capture_repair({**item,'recipe':RECIPE}) for item in train],
                     'validation':[case('fourth','m','n','d.py'),case('fifth','lhs','rhs','e.py')]}
                self.assertEqual(send('/v1/code/study',req)[0],403)
                self.assertEqual(send('/v1/code/study',req,True)[1]['promotion']['status'],'active')
                preview={'namespace':'code_http','source':'def new(a,b):\n return a-b\n',
                         'filename':'new.py','function':'new'}
                status,body=send('/v1/code/preview',preview)
                self.assertEqual(status,200)
                self.assertEqual(body['status'],'preview')
                self.assertIn('a + b',body['patched_source'])
                self.assertEqual(send('/v1/code/retire',{'namespace':'code_http','recipe_id':body['recipe_id']})[0],403)
            finally:
                proc.terminate()
                try:proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill();proc.wait(timeout=4)

if __name__=='__main__':unittest.main()
