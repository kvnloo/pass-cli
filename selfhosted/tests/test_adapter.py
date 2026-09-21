import importlib.util
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "pass_cli_local.py"
spec = importlib.util.spec_from_file_location("pass_cli_local", MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class AdapterTest(unittest.TestCase):
    def test_rpc_framing_and_auth_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "passd.sock"
            received = {}
            ready = threading.Event()

            def server():
                srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                srv.bind(str(path))
                srv.listen(1)
                ready.set()
                conn, _ = srv.accept()
                with conn:
                    buf = b""
                    while b"\n" not in buf:
                        buf += conn.recv(65536)
                    received.update(json.loads(buf.split(b"\n", 1)[0]))
                    conn.sendall(json.dumps({"ok": True, "result": {"version": 1}}).encode() + b"\n")
                srv.close()

            t = threading.Thread(target=server, daemon=True)
            t.start()
            self.assertTrue(ready.wait(2))
            out = mod.RpcClient(path).call("health", {"x": 1}, agent_token="pda_test.secret", reason="test")
            t.join(2)
            self.assertEqual(out, {"version": 1})
            self.assertEqual(received["op"], "health")
            self.assertEqual(received["agent_token"], "pda_test.secret")
            self.assertEqual(received["reason"], "test")

    def test_parse_ttl(self):
        self.assertEqual(mod.parse_ttl("1h"), 3600)
        self.assertEqual(mod.parse_ttl("15m"), 900)


if __name__ == "__main__":
    unittest.main()
