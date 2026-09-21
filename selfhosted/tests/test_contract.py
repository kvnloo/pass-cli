from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

BACKEND_ROOT = os.environ.get("PASSD_BACKEND_ROOT")
if not BACKEND_ROOT:
    raise unittest.SkipTest("set PASSD_BACKEND_ROOT=/path/to/passd-backend to run contract tests")
sys.path.insert(0, BACKEND_ROOT)

from passd.config import Config
from passd.server import PassdUnixServer
from passd.service import PassdService

MASTER = "contract-master"
SECRET = "contract-secret"
HERE = Path(__file__).resolve().parents[1]
ADAPTER = HERE / "pass_cli_local.py"


class Handler(BaseHTTPRequestHandler):
    def _serve(self):
        if self.headers.get("Authorization") != f"Bearer {SECRET}":
            self.send_response(401); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "auth": self.headers.get("Authorization")}).encode())
    def do_GET(self): self._serve()
    def do_POST(self): self._serve()
    def log_message(self, format, *args): pass


class AdapterContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.cfg = Config.initialize(self.root, MASTER)
        self.service = PassdService(self.cfg, self.cfg.derive_and_verify(MASTER), allow_private_broker_targets=True)
        self.server = PassdUnixServer(self.cfg.socket_path, self.service)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.http = HTTPServer(("127.0.0.1", 0), Handler)
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True); self.http_thread.start()
        self.base_env = {**os.environ, "PASSD_MASTER_PASSWORD": MASTER}

    def tearDown(self):
        self.http.shutdown(); self.http.server_close(); self.server.shutdown(); self.server.server_close(); self.service.close(); self.tmp.cleanup()

    def cli(self, *args, env=None, ok=True):
        cp = subprocess.run([sys.executable, str(ADAPTER), "--data-dir", str(self.root), *args], text=True, capture_output=True, env=env or self.base_env)
        if ok and cp.returncode != 0:
            self.fail(f"CLI failed: {cp.stderr}\nstdout={cp.stdout}")
        return cp

    def test_machine_api_key_rotation_via_adapter(self):
        agent = json.loads(self.cli("agent", "create", "rotate-me", "--expiration", "1h").stdout)
        old_token = agent["token"]
        rotated = json.loads(self.cli("agent", "rotate", agent["id"]).stdout)
        self.assertEqual(rotated["id"], agent["id"])
        self.assertNotEqual(rotated["token"], old_token)
        old_env = {**self.base_env, "PASSD_AGENT_TOKEN": old_token}
        new_env = {**self.base_env, "PASSD_AGENT_TOKEN": rotated["token"]}
        old = self.cli("capability", "list", env=old_env, ok=False)
        self.assertIn("auth_error", old.stderr)
        self.assertEqual(json.loads(self.cli("capability", "list", env=new_env).stdout), [])

    def test_zero_grant_request_approve_broker_flow(self):
        self.cli("vault", "create", "Personal")
        self.cli("item", "put-login", "--vault", "Personal", "--title", "Critical API", "--password", SECRET)
        agent = json.loads(self.cli("agent", "create", "hermes", "--scope", "access.request", "--scope", "metadata.read", "--scope", "secret.use", "--expiration", "1h").stdout)
        token = agent["token"]
        agent_env = {**self.base_env, "PASSD_AGENT_TOKEN": token, "PASSD_AGENT_REASON": "contract test"}

        self.assertEqual(json.loads(self.cli("vault", "list", env=agent_env).stdout), [])
        req = json.loads(self.cli("access", "request", "pass://Personal/Critical%20API/password", "--host", "127.0.0.1", "--uses", "2", env=agent_env).stdout)
        self.assertEqual(req["status"], "pending")
        self.cli("access", "approve", req["id"], "--uses", "2")
        self.assertEqual([v["name"] for v in json.loads(self.cli("vault", "list", env=agent_env).stdout)], ["Personal"])

        reveal = self.cli("resolve", "pass://Personal/Critical%20API/password", env=agent_env, ok=False)
        self.assertNotEqual(reveal.returncode, 0)
        self.assertIn("permission_denied", reveal.stderr)

        result = json.loads(self.cli(
            "broker-http", "pass://Personal/Critical%20API/password", f"http://127.0.0.1:{self.http.server_port}/check", env=agent_env
        ).stdout)
        self.assertEqual(result["status"], 200)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_v3_typed_capability_hides_backing_and_invokes_after_hitl(self):
        self.cli("vault", "create", "Personal")
        self.cli("item", "put-login", "--vault", "Personal", "--title", "OpenRouter", "--password", SECRET)
        cap = json.loads(self.cli(
            "capability", "put-http", "openrouter.infer",
            "--description", "Inference", "--backing-uri", "pass://Personal/OpenRouter/password",
            "--scheme", "http", "--host", "127.0.0.1", "--port", str(self.http.server_port),
            "--method", "POST", "--path-prefix", "/api/v1/chat/completions",
            "--static-header", "Content-Type=application/json",
        ).stdout)
        self.assertTrue(cap["version"].startswith("cv1_"))
        agent = json.loads(self.cli("agent", "create", "cap-hermes", "--expiration", "1h").stdout)
        agent_env = {**self.base_env, "PASSD_AGENT_TOKEN": agent["token"], "PASSD_AGENT_REASON": "typed capability contract"}

        catalog = json.loads(self.cli("capability", "list", env=agent_env).stdout)
        raw = json.dumps(catalog)
        self.assertEqual([x["id"] for x in catalog], ["openrouter.infer"])
        self.assertNotIn("pass://", raw)
        self.assertNotIn("Personal", raw)

        denied = self.cli("capability", "invoke", "openrouter.infer", "--method", "POST", "--path", "/api/v1/chat/completions", "--body", "{}", env=agent_env, ok=False)
        self.assertIn("permission_denied", denied.stderr)
        req = json.loads(self.cli("capability", "request", "openrouter.infer", "--method", "POST", "--path", "/api/v1/chat/completions", "--uses", "1", env=agent_env).stdout)
        self.assertTrue(req["authority_digest"].startswith("ad1_"))
        pending = json.loads(self.cli("access", "pending").stdout)
        match = next(x for x in pending if x["id"] == req["id"])
        self.assertEqual(match["capability_id"], "openrouter.infer")
        self.assertNotIn("uri", match)
        self.cli("access", "approve", req["id"])
        result = json.loads(self.cli("capability", "invoke", "openrouter.infer", "--method", "POST", "--path", "/api/v1/chat/completions", "--body", "{}", env=agent_env).stdout)
        self.assertEqual(result["status"], 200)
        self.assertNotIn(SECRET, json.dumps(result))


if __name__ == "__main__": unittest.main()
