#!/usr/bin/env python3
"""Run CLI + authenticated loopback HTTP in a self-contained temp directory.

This is a local integration smoke test, NOT an independent qualification.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from sis import __version__

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    p = subprocess.run([sys.executable, '-m', 'sis', *map(str, args)], capture_output=True, text=True,
                       check=True, timeout=20)
    return json.loads(p.stdout)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / 'registry.sqlite3'
        ck = Path(tmp) / 'anchor.json'
        r = run('--db', db, 'train', ROOT/'examples'/'arithmetic_study.json')
        assert r['promotion']['status'] == 'active', r
        pred = run('--db', db, 'predict-batch', ROOT/'examples'/'predict_batch.json')
        assert pred['predicted'] == 3, pred
        assert [p['output'] for p in pred['results']] == [22, 4, 80]
        rid=r['promotion']['id']
        transfer_payload={'source_namespace':'arithmetic_demo','rule_id':rid,
                          'field_map':{'a':'left','b':'right'},'inputs':{'left':7,'right':3}}
        transfer_path=Path(tmp)/'transfer.json'
        transfer_path.write_text(json.dumps(transfer_payload))
        transfer_out=run('--db',db,'transfer',transfer_path)
        assert transfer_out['output']==10 and transfer_out['qualification']=='unvalidated_target_hypothesis'
        assert run('--db', db, 'anchor-export', ck)['created']
        assert run('--db', db, 'anchor-verify', ck)['valid']
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        api_key='local_integration_key_for_tests_24_chars'
        env = dict(os.environ, SIS_API_KEY=api_key, SIS_ADMIN_KEY='operator_secret_1234567890_123456789')
        server = subprocess.Popen([sys.executable, '-m', 'sis', '--db', str(db),
                                   'serve', '--host', '127.0.0.1', '--port', str(port)],
                                  cwd=ROOT, env=env, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE)
        try:
            base = f'http://127.0.0.1:{port}'
            for _ in range(40):
                if server.poll() is not None:
                    raise RuntimeError('HTTP server exited before readiness')
                try:
                    with urlopen(Request(base+'/health', headers={'X-SIS-Key':api_key}), timeout=0.2) as conn:
                        assert json.load(conn)['version']==__version__
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError('HTTP server did not start')
            transfer_req=Request(base+'/v1/transfer',data=transfer_path.read_bytes(),
                                 headers={'X-SIS-Key':api_key,'Content-Type':'application/json'})
            with urlopen(transfer_req,timeout=2) as conn:
                assert json.load(conn)['output']==10
            body=(ROOT/'examples'/'predict_batch.json').read_bytes()
            req=Request(base+'/v1/predict-batch', data=body,
                        headers={'X-SIS-Key':api_key,'Content-Type':'application/json'})
            with urlopen(req,timeout=2) as conn:
                http_prediction=json.load(conn)
            assert http_prediction['predicted']==3, http_prediction
            try:
                urlopen(Request(base+'/v1/rules'),timeout=2)
                raise RuntimeError('HTTP endpoint failed to reject unauthenticated request')
            except HTTPError as exc:
                assert exc.code==401, exc.code
            # Read/predict token never authorizes promotion, even if supplied.
            try:
                urlopen(Request(base+'/v1/induce', data=(ROOT/'examples'/'arithmetic_study.json').read_bytes(),
                                headers={'X-SIS-Key':api_key, 'Content-Type':'application/json'}), timeout=5)
                raise RuntimeError('read-only API token could promote a rule')
            except HTTPError as exc:
                assert exc.code==403, exc.code
            with urlopen(Request(base+'/v1/induce', data=(ROOT/'examples'/'arithmetic_study.json').read_bytes(),
                                 headers={'X-SIS-Key':api_key,
                                          'X-SIS-Admin-Key':'operator_secret_1234567890_123456789',
                                          'Content-Type':'application/json'}), timeout=5) as conn:
                assert json.load(conn)['status'] == 'locally_validated'
            print(json.dumps({'success':True, 'train_promoted':True,
                              'cli_predictions':pred['predicted'],
                              'audit_anchor_verified':True,
                              'http_predictions':http_prediction['predicted'],
                              'http_unauthenticated_status':401,
                              'read_token_mutation_status':403, 'operator_mutation_status':200,
                              'qualification':'local integration smoke only'},indent=2))
        finally:
            server.terminate()
            try:
                server.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=3)


if __name__=='__main__':
    main()
