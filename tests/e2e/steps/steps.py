import os
import tempfile
import time

import requests
from behave import given, then, when

from helpers import (
    MockBackend,
    UpstreamerProcess,
    generate_config,
    http_status_codes,
    metrics_url,
    proxy_url,
    proxy_url_kubernetes,
)

# --- Given steps ---


@given("{n:d} backends running on ports {ports}")
def given_n_backends(context, n, ports):
    port_list = [int(p.strip()) for p in ports.split(",")]
    assert len(port_list) == n
    context.backends = []
    for port in port_list:
        backend = MockBackend(port)
        backend.start()
        context.backends.append(backend)


@given("1 backend running on port {port:d}")
def given_1_backend(context, port):
    context.backends = [MockBackend(port)]
    context.backends[0].start()


@given('a backend on port {port:d} responding "{body}"')
def given_backend_responding(context, port, body):
    backend = MockBackend(port, body=body.encode())
    backend.start()
    context.backends = [backend]


@given("a backend on port {port:d}")
def given_backend_plain(context, port):
    backend = MockBackend(port)
    backend.start()
    if not context.backends:
        context.backends = []
    context.backends.append(backend)


@given("a backend on port {port:d} returning status {status:d}")
def given_backend_status(context, port, status):
    backend = MockBackend(port, status=status)
    backend.start()
    if not context.backends:
        context.backends = []
    context.backends.append(backend)


@given("a slow backend on port {port:d} with {delay:d}ms delay")
def given_slow_backend(context, port, delay):
    backend = MockBackend(port, delay=delay / 1000.0)
    backend.start()
    if not context.backends:
        context.backends = []
    context.backends.append(backend)


@given("upstreamer is configured with round-robin across all 3 backends")
def given_config_rr_3(context):
    origins = [b.url for b in context.backends]
    _start_upstreamer(
        context,
        [
            {
                "pools": [{"name": "backend", "origins": origins}],
            }
        ],
    )


@given("upstreamer is configured with round-robin across 1 backend")
def given_config_rr_1(context):
    origins = [context.backends[0].url]
    _start_upstreamer(
        context,
        [{"pools": [{"name": "backend", "origins": origins}]}],
    )


@given("upstreamer is configured with round-robin across ports {ports}")
def given_config_rr_ports(context, ports):
    port_list = [int(p.strip()) for p in ports.split(",")]
    origins = [f"http://127.0.0.1:{p}" for p in port_list]
    context._current_ports = port_list
    _start_upstreamer(
        context,
        [{"pools": [{"name": "backend", "origins": origins}]}],
    )


@given("upstreamer is configured with weighted-latency balancing")
def given_config_weighted_latency(context):
    origins = [b.url for b in context.backends]
    _start_upstreamer(
        context,
        [{"algo": "weighted_latency", "pools": [{"name": "backend", "origins": origins}]}],
    )


@given("upstreamer is configured with a rate limit of {rate:d} requests/sec burst {burst:d}")
def given_config_ratelimit(context, rate, burst):
    origins = [b.url for b in context.backends]
    _start_upstreamer(
        context,
        [{"pools": [{"name": "backend", "origins": origins}]}],
        ratelimit={"rate": rate, "burst": burst},
    )


@given("upstreamer is configured with routes:")
def given_config_routes_table(context):
    routes = []
    for row in context.table:
        route = {}
        if row.get("host"):
            route["host"] = row["host"]
        if row.get("path"):
            route["path"] = row["path"]
        origins_str = row.get("origins", "")
        origins = [o.strip() for o in origins_str.split(",") if o.strip()]
        route["pools"] = [{"name": "backend", "origins": origins}]

        if row.get("rate"):
            route["ratelimit"] = {
                "rate": int(row["rate"]),
                "burst": int(row.get("burst", row["rate"])),
            }

        routes.append(route)
    _start_upstreamer(context, routes)


@given("a kind cluster running upstreamer from the Kubernetes manifests")
def given_kind_cluster(context):
    context.kind_cluster = context.shared_kind_cluster
    context.kind_cluster.start()


# --- When steps ---


@when("I send {n:d} requests to the proxy")
def when_send_n_requests(context, n):
    context.responses = []
    for _ in range(n):
        try:
            resp = requests.get(proxy_url(), timeout=5)
            context.responses.append(resp)
        except requests.RequestException as e:
            context.responses.append(e)


@when('I send a request to "{path}"')
def when_send_one_request(context, path):
    context.responses = []
    try:
        resp = requests.get(proxy_url(path), timeout=5)
        context.responses.append(resp)
    except requests.RequestException as e:
        context.responses.append(e)


@when('I send a request with host "{host}" to "{path}"')
def when_send_with_host(context, host, path):
    context.responses = []
    try:
        resp = requests.get(proxy_url(path), headers={"Host": host}, timeout=5)
        context.responses.append(resp)
    except requests.RequestException as e:
        context.responses.append(e)


@when('I send {n:d} requests to "{path}"')
def when_send_n_to_path(context, n, path):
    if not hasattr(context, "responses_by_path"):
        context.responses_by_path = {}
    context.responses_by_path[path] = []
    context.responses = []
    for _ in range(n):
        try:
            resp = requests.get(proxy_url(path), timeout=5)
            context.responses.append(resp)
            context.responses_by_path[path].append(resp)
        except requests.RequestException:
            pass


@when("I add backend on port {port:d} to the running config")
def when_add_backend_to_config(context, port):
    backend = MockBackend(port)
    backend.start()
    context.backends.append(backend)
    new_ports = context._current_ports + [port]
    _rewrite_config(context, new_ports)


@when("I remove backend on port {port:d} from the running config")
def when_remove_backend_from_config(context, port):
    context._new_ports = [p for p in context._current_ports if p != port]
    _rewrite_config(context, context._new_ports)


@when("I replace the running config with invalid content")
def when_write_invalid_config(context):
    with open(context.config_file, "w") as f:
        f.write("this is not valid toml [[[[\n")


@when("I wait for config reload")
def when_wait_for_reload(context):
    time.sleep(2.5)


@when("I send {count:d} rapid requests to the Kubernetes proxy")
def when_send_rapid_kubernetes_requests(context, count):
    context.kubernetes_statuses = http_status_codes(proxy_url_kubernetes(), count)


@when("I patch the Kubernetes config rate limit to {rate:d} requests/sec burst {burst:d}")
def when_patch_kubernetes_rate_limit(context, rate, burst):
    context.kind_cluster.patch_rate_limit(rate, burst)


@when("I wait {seconds:d} seconds for the Kubernetes config reload")
def when_wait_for_kubernetes_reload(context, seconds):
    time.sleep(seconds)


@then("I wait for Kubernetes self-metrics to be collected")
def then_wait_for_kubernetes_self_metrics(context):
    time.sleep(5)


# --- Then steps ---


@then("each backend should have received approximately {n:d} requests")
def then_each_approx_n(context, n):
    tolerance = n * 0.5
    for i, backend in enumerate(context.backends):
        actual = backend.request_count
        assert abs(actual - n) <= tolerance, (
            f"backend {i} got {actual} requests, expected ~{n} (tolerance ±{tolerance})"
        )


@then("the backend should have received {n:d} requests")
def then_backend_received_n(context, n):
    actual = context.backends[0].request_count
    assert actual >= n, f"backend received {actual} requests, expected at least {n}"


@then('the backend should have received requests to "{path}"')
def then_backend_received_path(context, path):
    for req in context.backends[0].received_requests:
        if req == path:
            return
    assert False, f"no request to '{path}' found. got: {context.backends[0].received_requests}"


@then("all responses should have status {status:d}")
def then_all_status(context, status):
    for i, resp in enumerate(context.responses):
        if isinstance(resp, Exception):
            assert False, f"request {i} failed: {resp}"
        assert resp.status_code == status, f"response {i} was {resp.status_code}, expected {status}"


@then("at least one response should have status {status:d}")
def then_at_least_one_status(context, status):
    found = any(hasattr(r, "status_code") and r.status_code == status for r in context.responses)
    statuses = [getattr(r, "status_code", "error") for r in context.responses]
    assert found, f"no response with status {status}. got: {statuses}"


@then('at least one response to "{path}" should have status {status:d}')
def then_at_least_one_path_status(context, path, status):
    responses = context.responses_by_path.get(path, [])
    found = any(hasattr(r, "status_code") and r.status_code == status for r in responses)
    statuses = [getattr(r, "status_code", "error") for r in responses]
    assert found, f"no response to {path} with status {status}. got: {statuses}"


@then('all responses to "{path}" should have status {status:d}')
def then_all_path_status(context, path, status):
    responses = context.responses_by_path.get(path, [])
    for i, resp in enumerate(responses):
        if isinstance(resp, Exception):
            assert False, f"request {i} to {path} failed: {resp}"
        assert resp.status_code == status, (
            f"response {i} to {path} was {resp.status_code}, expected {status}"
        )


@then('the response body should contain "{text}"')
def then_body_contains(context, text):
    resp = context.responses[0]
    assert text in resp.text, f"response body '{resp.text}' does not contain '{text}'"


@then("the response status should be {status:d}")
def then_status(context, status):
    resp = context.responses[0]
    assert resp.status_code == status, f"response status was {resp.status_code}, expected {status}"


@then("backend {port:d} should have received most of the requests")
def then_backend_most(context, port):
    target = None
    other_total = 0
    for backend in context.backends:
        if backend.port == port:
            target = backend
        else:
            other_total += backend.request_count
    assert target is not None, f"no backend on port {port}"
    assert target.request_count > other_total, (
        f"backend {port} got {target.request_count}, others got {other_total}"
    )


@then("the proxy should still respond with 502")
def then_proxy_responds_502(context):
    statuses = [r.status_code for r in context.responses if hasattr(r, "status_code")]
    assert 502 in statuses, f"expected at least one 502, got statuses: {statuses}"


@then("backend {port:d} should have received at least {n:d} requests")
def then_backend_at_least_n(context, port, n):
    for backend in context.backends:
        if backend.port == port:
            actual = backend.request_count
            assert actual >= n, f"backend {port} got {actual} requests, expected at least {n}"
            return
    assert False, f"no backend on port {port}"


@then("backend {port:d} should have received at most {n:d} requests")
def then_backend_at_most_n(context, port, n):
    for backend in context.backends:
        if backend.port == port:
            actual = backend.request_count
            assert actual <= n, f"backend {port} got {actual} requests, expected at most {n}"
            return
    assert False, f"no backend on port {port}"


@then("the Kubernetes proxy should route to the backend")
def then_kubernetes_proxy_routes(context):
    response = requests.get(proxy_url_kubernetes(), timeout=5)
    assert response.status_code == 200, f"expected 200, got {response.status_code}"
    assert "backend ok" in response.text, f"unexpected response body: {response.text[:100]}"


@then("the Kubernetes health endpoint should return status {status:d}")
def then_kubernetes_health_status(context, status):
    response = requests.get(metrics_url("/healthz", kubernetes=True), timeout=5)
    assert response.status_code == status, f"expected {status}, got {response.status_code}"


@then('the Kubernetes metrics should contain "{text}"')
def then_kubernetes_metrics_contains(context, text):
    response = requests.get(metrics_url(kubernetes=True), timeout=5)
    assert response.status_code == 200, f"expected 200, got {response.status_code}"
    assert text in response.text, f"metrics did not contain '{text}'"


@then("at least {count:d} Kubernetes responses should have status {status:d}")
def then_kubernetes_at_least_status(context, count, status):
    matches = sum(1 for code in context.kubernetes_statuses if code == status)
    assert matches >= count, f"expected at least {count} responses with {status}, got {matches}"


@then("more than {count:d} Kubernetes responses should have status {status:d}")
def then_kubernetes_more_than_status(context, count, status):
    matches = sum(1 for code in context.kubernetes_statuses if code == status)
    assert matches > count, f"expected more than {count} responses with {status}, got {matches}"


# --- Helpers ---


def _start_upstreamer(context, routes, ratelimit=None):
    toml_config = generate_config(routes, ratelimit=ratelimit)
    fd, path = tempfile.mkstemp(suffix=".toml")
    with os.fdopen(fd, "w") as f:
        f.write(toml_config)
    context.config_file = path
    context.upstreamer = UpstreamerProcess(path)
    context.upstreamer.start()



def _rewrite_config(context, ports):
    origins = [f"http://127.0.0.1:{p}" for p in ports]
    routes = [{"pools": [{"name": "backend", "origins": origins}]}]
    toml_config = generate_config(routes)
    with open(context.config_file, "w") as f:
        f.write(toml_config)
    context._current_ports = ports
