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

from sis.server import OPERATOR_POST_ROUTES, POST_ROUTE_ACCESS, POST_ROUTE_HANDLERS, READ_ONLY_POST_ROUTES


ROOT = Path(__file__).resolve().parents[2]


class ServerProcess:
    def __init__(self, directory, *, keyed):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.env = {key: value for key, value in os.environ.items()
                    if key not in {"SIS_API_KEY", "SIS_ADMIN_KEY", "SIS_ENABLE_LLM"}}
        self.env["PYTHONPATH"] = str(ROOT / "src")
        if keyed:
            self.env["SIS_API_KEY"] = "reader-key-for-v3-auth-tests-0001"
            self.env["SIS_ADMIN_KEY"] = "separate-operator-key-for-tests-0001"
        self.process = subprocess.Popen(
            [sys.executable, "-m", "sis", "--db", str(Path(directory) / "sis.sqlite3"),
             "serve", "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=ROOT, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            if self.process.poll() is not None:
                raise AssertionError("SIS HTTP server exited before readiness")
            try:
                response = self.request("GET", "/health", {}, reader=keyed)
                if response[0] == 200:
                    break
            except OSError:
                time.sleep(0.05)
        else:
            self.close()
            raise AssertionError("SIS HTTP server did not become ready")

    def request(self, method, path, body, *, reader=False, admin_key=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        headers = {"Content-Type": "application/json"}
        if reader:
            headers["X-SIS-Key"] = self.env["SIS_API_KEY"]
        if admin_key is not None:
            headers["X-SIS-Admin-Key"] = admin_key
        connection.request(method, path, json.dumps(body), headers=headers)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=4)


class V3HttpPermissionTests(unittest.TestCase):
    def test_all_dispatch_routes_have_explicit_policy(self):
        self.assertEqual(set(POST_ROUTE_HANDLERS), set(POST_ROUTE_ACCESS))
        self.assertEqual(set(POST_ROUTE_ACCESS[path] for path in OPERATOR_POST_ROUTES), {"operator"})
        self.assertEqual(set(POST_ROUTE_ACCESS[path] for path in READ_ONLY_POST_ROUTES), {"reader"})
        self.assertTrue(OPERATOR_POST_ROUTES.isdisjoint(READ_ONLY_POST_ROUTES))

    def test_reader_token_and_forged_json_role_cannot_mutate_any_admin_route(self):
        with tempfile.TemporaryDirectory() as temp:
            server = ServerProcess(temp, keyed=True)
            try:
                forged = {"role": "operator", "actor": "operator", "action": "promotion:approve"}
                for path in sorted(OPERATOR_POST_ROUTES):
                    with self.subTest(path=path):
                        status, body = server.request("POST", path, forged, reader=True)
                        self.assertEqual(403, status, body)
                        self.assertIn("authorization", body["error"])
                status, _ = server.request("POST", "/v1/code/study", forged, reader=True,
                                           admin_key="attacker-controlled-not-the-admin-key")
                self.assertEqual(403, status)
            finally:
                server.close()

    def test_path_aliases_do_not_reach_mutation_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            server = ServerProcess(temp, keyed=True)
            try:
                forged = {"role": "operator", "promote": True}
                for path in ("/v1/%69nduce", "/v1/induce/", "/v1//induce"):
                    with self.subTest(path=path):
                        status, _ = server.request("POST", path, forged, reader=True)
                        self.assertEqual(404, status)
                status, _ = server.request("POST", "/v1/induce?alias=1", forged, reader=True)
                self.assertEqual(403, status)
            finally:
                server.close()

    def test_unkeyed_loopback_demo_mutation_remains_compatible(self):
        request = json.loads((ROOT / "examples/v2_4/code_study.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp:
            server = ServerProcess(temp, keyed=False)
            try:
                status, body = server.request("POST", "/v1/code/study", request)
                self.assertEqual(200, status, body)
                self.assertEqual("active", body["promotion"]["status"])
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
