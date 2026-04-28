import os
import subprocess
import time
import threading
import tempfile
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler

PROXY_PORT = 19080
METRICS_PORT = 19090
BACKEND_BASE_PORT = 19101
UPSTREAMER_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "target",
    "release",
    "upstreamer",
)


def make_handler(status=200, body=b"ok", headers=None, delay=0):
    class Handler(BaseHTTPRequestHandler):
        request_count = 0
        received_requests = []

        def do_GET(self):
            if delay > 0:
                time.sleep(delay)
            Handler.request_count += 1
            Handler.received_requests.append(self.path)
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            request_body = self.rfile.read(length) if length else b""
            Handler.request_count += 1
            Handler.received_requests.append(
                {"path": self.path, "method": "POST", "body": request_body}
            )
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


class MockBackend:
    def __init__(self, port, status=200, body=b"ok", headers=None, delay=0):
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        handler = make_handler(status, body, headers, delay=delay)
        self.server = HTTPServer(("127.0.0.1", port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._handler = handler

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    @property
    def request_count(self):
        return self._handler.request_count

    @property
    def received_requests(self):
        return self._handler.received_requests


def generate_config(routes, proxy_port=PROXY_PORT, metrics_port=METRICS_PORT,
                    ratelimit=None, health_active=False):
    lines = [
        f'listen = "127.0.0.1:{proxy_port}"',
        f'metrics_addr = "127.0.0.1:{metrics_port}"',
    ]

    if ratelimit:
        lines.append("[ratelimit]")
        lines.append(f'rate = {ratelimit["rate"]}')
        lines.append(f'burst = {ratelimit["burst"]}')

    lines.append("[health]")
    lines.append(f'[health.active]')
    lines.append(f'enabled = {"true" if health_active else "false"}')
    lines.append('interval = "5s"')
    lines.append('timeout = "2s"')
    lines.append("[health.passive]")
    lines.append("enabled = true")
    lines.append("failure_threshold = 3")
    lines.append("success_threshold = 2")

    for route in routes:
        lines.append("[[routes]]")
        if route.get("host"):
            lines.append(f'match_host = "{route["host"]}"')
        if route.get("path"):
            lines.append(f'match_path = "{route["path"]}"')
        lines.append(f'lb_algorithm = "{route.get("algo", "round_robin")}"')
        if route.get("ratelimit"):
            rl = route["ratelimit"]
            lines.append("[routes.ratelimit]")
            lines.append(f'rate = {rl["rate"]}')
            lines.append(f'burst = {rl["burst"]}')
        for pool in route.get("pools", []):
            lines.append("[[routes.pools]]")
            lines.append(f'name = "{pool["name"]}"')
            for origin in pool.get("origins", []):
                lines.append("[[routes.pools.origins]]")
                if isinstance(origin, dict):
                    lines.append(f'url = "{origin["url"]}"')
                    if origin.get("weight"):
                        lines.append(f'weight = {origin["weight"]}')
                else:
                    lines.append(f'url = "{origin}"')

    return "\n".join(lines) + "\n"


class UpstreamerProcess:
    def __init__(self, config_path, proxy_port=PROXY_PORT):
        self.config_path = config_path
        self.proxy_port = proxy_port
        self.process = None

    def start(self):
        self.process = subprocess.Popen(
            [UPSTREAMER_BIN, "--config", self.config_path, "--log-level", "warn"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            try:
                requests.get(f"http://127.0.0.1:{self.proxy_port}/", timeout=0.1)
                return True
            except requests.ConnectionError:
                time.sleep(0.1)
        raise RuntimeError("upstreamer failed to start")

    def stop(self):
        if self.process:
            self.process.kill()
            self.process.wait(timeout=5)
            self.process = None


def proxy_url(path="/"):
    return f"http://127.0.0.1:{PROXY_PORT}{path}"


def reset_handler(handler_class):
    handler_class.request_count = 0
    handler_class.received_requests = []
