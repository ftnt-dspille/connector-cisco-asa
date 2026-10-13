"""Offline fixtures for the Cisco ASA connector.

Stubs the FortiSOAR SDK and paramiko, registers the hyphenated connector
directory as the package ``ciscoasa_pkg``, and serves a fake ASA REST API on
a loopback port (HTTP basic auth check).
"""

import base64
import json
import logging
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

CONNECTOR_DIR = Path(__file__).resolve().parent.parent / 'cisco-asa'

if 'connectors' not in sys.modules:
    _connectors = types.ModuleType('connectors')
    _connectors.__path__ = []
    _core = types.ModuleType('connectors.core')
    _core.__path__ = []
    _mod = types.ModuleType('connectors.core.connector')

    class ConnectorError(Exception):
        pass

    class Connector:
        pass

    _mod.ConnectorError = ConnectorError
    _mod.Connector = Connector
    _mod.get_logger = logging.getLogger
    _core.connector = _mod
    _connectors.core = _core
    sys.modules['connectors'] = _connectors
    sys.modules['connectors.core'] = _core
    sys.modules['connectors.core.connector'] = _mod

for _name in ('paramiko', 'validators'):
    if _name not in sys.modules:
        try:
            __import__(_name)
        except ImportError:
            sys.modules[_name] = types.ModuleType(_name)

if 'ciscoasa_pkg' not in sys.modules:
    _pkg = types.ModuleType('ciscoasa_pkg')
    _pkg.__path__ = [str(CONNECTOR_DIR)]
    sys.modules['ciscoasa_pkg'] = _pkg

USER, PASSWORD = 'admin', 'pw-for-tests'


class State:
    def __init__(self):
        self.port = 0
        self.seen = []


STATE = State()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body):
        payload = json.dumps(body).encode() if body is not None else b''
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        expected = 'Basic ' + base64.b64encode(
            '{0}:{1}'.format(USER, PASSWORD).encode()).decode()
        STATE.seen.append({'method': self.command, 'path': self.path, 'body': body,
                           'auth': self.headers.get('Authorization'),
                           'agent': self.headers.get('User-Agent')})
        if self.headers.get('Authorization') != expected:
            self._send(401, {'messages': [{'code': 'unauthorized'}]})
        elif self.path.startswith('/api/monitoring/serialnumber'):
            self._send(200, {'kind': 'object#serialnumber', 'serialNumber': 'TEST123'})
        elif self.path.startswith('/api/objects/networkobjects'):
            self._send(201 if self.command == 'POST' else 204 if self.command == 'DELETE' else 200,
                       {'echo': body} if self.command == 'POST' else None)
        else:
            self._send(404, {'messages': [{'code': 'not found'}]})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


@pytest.fixture()
def fake():
    STATE.seen = []
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    STATE.port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield STATE
    server.shutdown()
    server.server_close()


@pytest.fixture()
def config(fake):
    return {'server_url': '127.0.0.1:{0}'.format(fake.port), 'username': USER,
            'password': PASSWORD, 'verify_ssl': False}


@pytest.fixture(autouse=True)
def loopback_http(monkeypatch):
    """The connector always speaks https; the loopback fake speaks plain http."""
    import requests
    real = requests.request

    def request(method, url, **kw):
        assert url.startswith('https://127.0.0.1:'), url
        return real(method, 'http://' + url[len('https://'):], **kw)

    monkeypatch.setattr(requests, 'request', request)
