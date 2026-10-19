"""Narrow, opt-in loopback broker for elevated Windows ETW observation.

The web API remains unelevated. This process can only start a fixed process
provider trace, stop it, and return bounded PID-correlated lifecycle metadata.
It never accepts a provider, command, filesystem path, or output filename from
the client. The random per-demo token is kept outside source control.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import uuid

from .windows_etw import EtwActionObserver, availability as direct_availability


ROOT = Path(__file__).resolve().parents[1]
TOKEN_FILE = ROOT / ".data" / "faculty-demo" / "etw-broker-token"
TRACE_ROOT = ROOT / ".data" / "faculty-demo" / "etw-broker"
URL_ENV = "AGENTSENTINEL_ETW_BROKER_URL"
TOKEN_ENV = "AGENTSENTINEL_ETW_BROKER_TOKEN"
MAX_SESSIONS = 4
MAX_BODY = 2048
SESSION_TTL_NS = 30_000_000_000


def configured() -> bool:
    return bool(os.environ.get(URL_ENV) and os.environ.get(TOKEN_ENV))


def _client_config() -> tuple[str, str]:
    url = os.environ.get(URL_ENV, "")
    token = os.environ.get(TOKEN_ENV, "")
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or
            parsed.port is None or parsed.path or parsed.query or parsed.fragment or
            not re.fullmatch(r"[0-9a-f]{64}", token)):
        raise ValueError("ETW_BROKER_CONFIGURATION_INVALID")
    return url.rstrip("/"), token


def _request(path: str, body: dict | None = None) -> dict:
    url, token = _client_config()
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
    request = Request(url + path, data=encoded,
                      headers={"X-AgentSentinel-Token": token,
                               "Content-Type": "application/json"},
                      method="POST" if body is not None else "GET")
    with urlopen(request, timeout=5) as response:
        if int(response.headers.get("Content-Length", "0")) > 16384:
            raise ValueError("ETW_BROKER_RESPONSE_TOO_LARGE")
        data = response.read(16385)
    if len(data) > 16384:
        raise ValueError("ETW_BROKER_RESPONSE_TOO_LARGE")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("ETW_BROKER_RESPONSE_INVALID")
    return value


def availability() -> dict:
    if not configured():
        return {"available": False, "reason": "ETW_BROKER_NOT_CONFIGURED"}
    try:
        response = _request("/health")
        return {"available": response.get("ready") is True,
                "reason": "ETW_BROKER_READY" if response.get("ready") is True else "ETW_BROKER_UNAVAILABLE"}
    except (OSError, ValueError, HTTPError, URLError, TimeoutError):
        return {"available": False, "reason": "ETW_BROKER_UNAVAILABLE"}


class BrokerEtwActionObserver:
    def __init__(self, directory: Path, request_id: str):
        del directory  # The elevated broker owns its fixed trace directory.
        self.request_id = request_id
        self.session_id: str | None = None
        self.status = {"status": "NOT_STARTED", "coverage": "NONE", "correlated": False}

    def start(self) -> dict:
        try:
            response = _request("/start", {"request_id": self.request_id})
            status = response.get("status")
            if not isinstance(status, dict):
                raise ValueError("ETW_BROKER_RESPONSE_INVALID")
            self.session_id = response.get("session_id") if status.get("status") == "RECORDING" else None
            if status.get("status") == "RECORDING" and (not isinstance(self.session_id, str) or
                    not re.fullmatch(r"[0-9a-f]{32}", self.session_id)):
                raise ValueError("ETW_BROKER_SESSION_INVALID")
            self.status = status
        except (OSError, ValueError, HTTPError, URLError, TimeoutError):
            self.status = {"status": "UNAVAILABLE", "reason": "ETW_BROKER_UNAVAILABLE",
                           "coverage": "NONE", "correlated": False}
        return self.status

    def stop(self, pid: int | None, started_ns: int | None) -> dict:
        if not self.session_id:
            return self.status
        try:
            status = _request("/stop", {"session_id": self.session_id,
                                         "pid": pid, "started_ns": started_ns})
            if not isinstance(status.get("status"), str):
                raise ValueError("ETW_BROKER_RESPONSE_INVALID")
            self.status = status
        except (OSError, ValueError, HTTPError, URLError, TimeoutError):
            self.status = {"status": "INCOMPLETE", "reason": "ETW_BROKER_STOP_FAILED",
                           "coverage": "PARTIAL_PROCESS_EVENTS", "correlated": False}
        finally:
            self.session_id = None
        return self.status


class _BrokerState:
    def __init__(self, token: str):
        self.token = token
        self.sessions: dict[str, tuple[EtwActionObserver, int]] = {}
        self.lock = threading.Lock()

    def reap_expired(self, now_ns: int) -> int:
        with self.lock:
            expired = [key for key, (_, started) in self.sessions.items()
                       if now_ns - started > SESSION_TTL_NS]
            entries = [self.sessions.pop(key) for key in expired]
        for observer, _ in entries:
            observer.stop(None, None)
        return len(entries)


class _Handler(BaseHTTPRequestHandler):
    server: "_BrokerServer"

    def log_message(self, *_args: object) -> None:
        pass

    def _reply(self, code: int, value: dict) -> None:
        encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _authorized(self) -> bool:
        return (self.client_address[0] == "127.0.0.1" and
                hmac.compare_digest(self.headers.get("X-AgentSentinel-Token", ""),
                                    self.server.state.token))

    def _body(self) -> dict | None:
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            return None
        if not 0 <= size <= MAX_BODY:
            return None
        try:
            value = json.loads(self.rfile.read(size))
        except (UnicodeDecodeError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def do_GET(self) -> None:
        if not self._authorized():
            self._reply(403, {"error": "FORBIDDEN"})
        elif self.path == "/health":
            self._reply(200, {"ready": True, "provider": "Microsoft-Windows-Kernel-Process"})
        else:
            self._reply(404, {"error": "NOT_FOUND"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._reply(403, {"error": "FORBIDDEN"})
            return
        body = self._body()
        if body is None:
            self._reply(400, {"error": "INVALID_BODY"})
            return
        state = self.server.state
        if self.path == "/start":
            request_id = body.get("request_id")
            if not isinstance(request_id, str) or not re.fullmatch(r"[a-zA-Z0-9:_-]{1,128}", request_id):
                self._reply(400, {"error": "INVALID_REQUEST_ID"})
                return
            with state.lock:
                if len(state.sessions) >= MAX_SESSIONS:
                    self._reply(429, {"error": "SESSION_LIMIT"})
                    return
                session_id = uuid.uuid4().hex
                observer = EtwActionObserver(TRACE_ROOT, request_id)
                status = observer.start()
                if status["status"] == "RECORDING":
                    state.sessions[session_id] = (observer, time.time_ns())
            self._reply(200, {"session_id": session_id if status["status"] == "RECORDING" else None,
                              "status": status})
        elif self.path == "/stop":
            session_id, pid, started_ns = body.get("session_id"), body.get("pid"), body.get("started_ns")
            if (not isinstance(session_id, str) or not re.fullmatch(r"[0-9a-f]{32}", session_id) or
                    (pid is not None and (type(pid) is not int or not 1 <= pid <= 0xffffffff)) or
                    (started_ns is not None and type(started_ns) is not int)):
                self._reply(400, {"error": "INVALID_STOP"})
                return
            with state.lock:
                entry = state.sessions.pop(session_id, None)
            if entry is None:
                self._reply(404, {"error": "SESSION_NOT_FOUND"})
                return
            observer, session_started_ns = entry
            now_ns = time.time_ns()
            if pid is None or started_ns is None:
                self._reply(200, observer.stop(None, None))
                return
            if (not session_started_ns - 1_000_000_000 <= started_ns <= now_ns or
                    now_ns - session_started_ns > 30_000_000_000):
                observer.stop(None, None)
                self._reply(400, {"error": "SESSION_WINDOW_INVALID"})
                return
            self._reply(200, observer.stop(pid, started_ns))
        elif self.path == "/shutdown":
            with state.lock:
                entries = list(state.sessions.values())
                state.sessions.clear()
            for observer, _ in entries:
                observer.stop(None, None)
            self._reply(200, {"stopping": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self._reply(404, {"error": "NOT_FOUND"})


class _BrokerServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, port: int, token: str):
        super().__init__(("127.0.0.1", port), _Handler)
        self.state = _BrokerState(token)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        raise SystemExit("INVALID_PORT")
    if not direct_availability()["available"]:
        raise SystemExit("ETW_TOOLS_UNAVAILABLE")
    from .secure_lab import integrity_status
    if not integrity_status()["valid"]:
        raise SystemExit("SOURCE_INTEGRITY_INVALID")
    token = TOKEN_FILE.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise SystemExit("BROKER_TOKEN_INVALID")
    TRACE_ROOT.mkdir(parents=True, exist_ok=True)
    server = _BrokerServer(args.port, token)
    closing = threading.Event()
    def reap_loop() -> None:
        while not closing.wait(2):
            server.state.reap_expired(time.time_ns())
    reaper = threading.Thread(target=reap_loop, daemon=True)
    reaper.start()
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        closing.set()
        reaper.join(timeout=3)
        server.server_close()
        with server.state.lock:
            entries = list(server.state.sessions.values())
            server.state.sessions.clear()
        for observer, _ in entries:
            observer.stop(None, None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
