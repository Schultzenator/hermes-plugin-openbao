from __future__ import annotations

import json
import importlib.util
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from agent.secret_sources.base import ErrorKind, set_source_environment, reset_source_environment
_PLUGIN_DIR = Path(__file__).parents[1]
sys.path.insert(0, str(_PLUGIN_DIR))
_SPEC = importlib.util.spec_from_file_location("openbao_plugin", _PLUGIN_DIR / "__init__.py")
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules["openbao_plugin"] = _MODULE
_SPEC.loader.exec_module(_MODULE)
OpenBaoSource = _MODULE.OpenBaoSource


class _Handler(BaseHTTPRequestHandler):
    calls: list[str] = []

    def do_GET(self):  # noqa: N802
        self.calls.append(self.path)
        if self.path == "/v1/kv/data/demo":
            body = {"data": {"data": {"api_key": "from-openbao", "count": 7}}}
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):
        return


def _server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_kv2_mapping_and_protected_token():
    server = _server()
    token = set_source_environment({"HERMES_OPENBAO_TOKEN": "test-token"})
    try:
        source = OpenBaoSource()
        result = source.fetch({
            "enabled": True,
            "vault_addr": f"http://127.0.0.1:{server.server_port}",
            "env": {"OPENAI_API_KEY": "bao://kv/demo#api_key", "COUNT": "bao://kv/demo#count"},
        }, Path("/tmp/hermes-openbao-test"))
        assert result.ok
        assert result.secrets == {"OPENAI_API_KEY": "from-openbao", "COUNT": "7"}
        assert source.protected_env_vars({}) == frozenset({"HERMES_OPENBAO_TOKEN"})
        assert _Handler.calls[-1] == "/v1/kv/data/demo"
    finally:
        reset_source_environment(token)
        server.shutdown()


def test_missing_token_is_fail_open_error():
    source = OpenBaoSource()
    token = set_source_environment({})
    try:
        result = source.fetch({"enabled": True, "env": {"X": "bao://kv/demo#key"}}, Path("/tmp"))
        assert result.error_kind is ErrorKind.NOT_CONFIGURED
        assert not result.secrets
    finally:
        reset_source_environment(token)


def test_invalid_refs_never_raise():
    token = set_source_environment({"HERMES_OPENBAO_TOKEN": "test-token"})
    try:
        result = OpenBaoSource().fetch({"enabled": True, "env": {"bad-name": "file:///etc/passwd"}}, Path("/tmp"))
    finally:
        reset_source_environment(token)
    assert result.error_kind is ErrorKind.REF_INVALID
