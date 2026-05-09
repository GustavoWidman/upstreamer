import json
import os
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import requests

PROXY_PORT = 19080
METRICS_PORT = 19090
BACKEND_BASE_PORT = 19101
REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_ROOT = Path(__file__).resolve().parent
KUBERNETES_DIR = E2E_ROOT / "kubernetes"
UPSTREAMER_BIN = os.path.join(REPO_ROOT, "target", "release", "upstreamer")
KIND_CLUSTER = "upstreamer-e2e"
KIND_PROXY_PORT = 18080
KIND_METRICS_PORT = 19090


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


def generate_config(
    routes, proxy_port=PROXY_PORT, metrics_port=METRICS_PORT, ratelimit=None, health_active=False
):
    lines = [
        f'listen = "127.0.0.1:{proxy_port}"',
        f'metrics_addr = "127.0.0.1:{metrics_port}"',
    ]

    if ratelimit:
        lines.append("[ratelimit]")
        lines.append(f'rate = {ratelimit["rate"]}')
        lines.append(f'burst = {ratelimit["burst"]}')

    lines.append("[health]")
    lines.append("[health.active]")
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
        wait_for_http_ok(f"http://127.0.0.1:{self.proxy_port}/", accept_5xx=True)
        return True

    def stop(self):
        if self.process:
            self.process.kill()
            self.process.wait(timeout=5)
            self.process = None


class KindCluster:
    def __init__(self, cluster_name=KIND_CLUSTER, assets_dir=KUBERNETES_DIR):
        self.cluster_name = cluster_name
        self.assets_dir = Path(assets_dir)
        self.port_forwards = []
        self.started = False

    def start(self):
        if self.started:
            self.reset_config()
            return

        self.delete()
        self._kind(
            "create",
            "cluster",
            "--name",
            self.cluster_name,
            "--config",
            str(self.assets_dir / "kind.yaml"),
            "--wait",
            "120s",
        )
        run_command(
            [
                "docker",
                "build",
                "-t",
                "upstreamer:latest",
                "-f",
                str(self.assets_dir / "Dockerfile"),
                ".",
            ],
            cwd=REPO_ROOT,
        )
        self._kind("load", "docker-image", "upstreamer:latest", "--name", self.cluster_name)
        self._kubectl("apply", "-f", str(self.assets_dir / "manifests" / "backend.yaml"))
        self._kubectl("rollout", "status", "deployment/backend", "--timeout=60s")
        self._kubectl("apply", "-f", str(self.assets_dir / "manifests" / "upstreamer.yaml"))
        self._kubectl("rollout", "status", "deployment/upstreamer", "--timeout=60s")
        self._start_port_forward("svc/upstreamer", KIND_PROXY_PORT, 8080)
        self._start_port_forward("svc/upstreamer", KIND_METRICS_PORT, 9090)
        self.started = True
        self.reset_config()

    def delete(self):
        self.stop_port_forwards()
        run_command(
            [
                "nix",
                "run",
                "nixpkgs#kind",
                "--",
                "delete",
                "cluster",
                "--name",
                self.cluster_name,
            ],
            check=False,
            cwd=REPO_ROOT,
        )
        self.started = False

    def cleanup(self):
        self.delete()

    def patch_rate_limit(self, rate, burst):
        self._patch_config(build_kubernetes_config(rate=rate, burst=burst))

    def reset_config(self):
        if not self.started:
            return
        self._patch_config(build_kubernetes_config())
        wait_for_http_ok(proxy_url_kubernetes())
        wait_for_http_status(metrics_url("/healthz", kubernetes=True), 200)

    def stop_port_forwards(self):
        for process in self.port_forwards:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        self.port_forwards = []

    def _kind(self, *args):
        run_command(["nix", "run", "nixpkgs#kind", "--", *args], cwd=REPO_ROOT)

    def _kubectl(self, *args):
        run_command(["nix", "run", "nixpkgs#kubectl", "--", *args], cwd=REPO_ROOT)

    def _patch_config(self, config):
        payload = {"data": {"upstreamer.toml": config}}
        self._kubectl(
            "patch",
            "configmap",
            "upstreamer-config",
            "--type",
            "merge",
            "-p",
            json.dumps(payload),
        )

    def _start_port_forward(self, resource, local_port, remote_port):
        process = subprocess.Popen(
            [
                "nix",
                "run",
                "nixpkgs#kubectl",
                "--",
                "port-forward",
                resource,
                f"{local_port}:{remote_port}",
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.port_forwards.append(process)
        wait_for_port_forward(local_port, process)


def build_kubernetes_config(rate=10, burst=10):
    return "\n".join(
        [
            'listen = "0.0.0.0:8080"',
            'metrics_addr = "0.0.0.0:9090"',
            "",
            "[health]",
            "[health.active]",
            "enabled = true",
            'interval = "5s"',
            'timeout = "3s"',
            "healthy_threshold = 2",
            "unhealthy_threshold = 3",
            "",
            "[health.passive]",
            "enabled = true",
            "failure_threshold = 5",
            "success_threshold = 2",
            'observation_window = "60s"',
            "",
            "[[routes]]",
            'match_path = "/"',
            'lb_algorithm = "round_robin"',
            "",
            "[routes.ratelimit]",
            f"rate = {rate}",
            f"burst = {burst}",
            "",
            "[[routes.pools]]",
            'name = "backend"',
            "",
            "[[routes.pools.origins]]",
            'url = "http://backend:80"',
            "",
            "[kubernetes]",
            'namespace = "default"',
            'label_selector = "app=backend"',
            "",
        ]
    )


def run_command(command, cwd=None, check=True):
    return subprocess.run(command, cwd=cwd, check=check, text=True)


def wait_for_http_ok(url, attempts=50, delay=0.2, accept_5xx=False):
    for _ in range(attempts):
        try:
            response = requests.get(url, timeout=0.2)
            if accept_5xx or response.status_code < 500:
                return response
        except requests.RequestException:
            pass
        time.sleep(delay)
    raise RuntimeError(f"service did not become ready: {url}")


def wait_for_http_status(url, expected_status, attempts=50, delay=0.2):
    last_status = None
    for _ in range(attempts):
        try:
            response = requests.get(url, timeout=1)
            last_status = response.status_code
            if response.status_code == expected_status:
                return response
        except requests.RequestException:
            last_status = "request failed"
        time.sleep(delay)
    raise AssertionError(f"expected {expected_status} from {url}, got {last_status}")


def wait_for_port_forward(port, process, attempts=50, delay=0.2):
    for _ in range(attempts):
        if process.poll() is not None:
            raise RuntimeError(f"port-forward exited early for port {port}")
        try:
            requests.get(f"http://127.0.0.1:{port}", timeout=0.1)
            return
        except requests.RequestException:
            time.sleep(delay)
    raise RuntimeError(f"port-forward did not become ready on port {port}")


def proxy_url(path="/"):
    return f"http://127.0.0.1:{PROXY_PORT}{path}"


def proxy_url_kubernetes(path="/"):
    return f"http://127.0.0.1:{KIND_PROXY_PORT}{path}"


def metrics_url(path="/metrics", kubernetes=False):
    port = KIND_METRICS_PORT if kubernetes else METRICS_PORT
    return f"http://127.0.0.1:{port}{path}"


def http_status_codes(url, count, timeout=3):
    statuses = []
    for _ in range(count):
        try:
            response = requests.get(url, timeout=timeout)
            statuses.append(response.status_code)
        except requests.RequestException:
            statuses.append(0)
    return statuses


def reset_handler(handler_class):
    handler_class.request_count = 0
    handler_class.received_requests = []
