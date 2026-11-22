"""httpx over HTTP/2 (the Python `h2` library) across a drain of the proxy on 127.0.0.1.

Usage: httpx_drain.py PORT

Two kept connections: one idle and one with a request to /slow in progress when the drain
starts. Each line on stdout is a response body: the first answer on each connection, then,
once a line on stdin says the drain has started, the next request on the idle connection,
the request in progress, and the next request on the other connection. A request that
fails ends the script with its error.
"""

import sys
import threading

import httpx

BASE = f"https://127.0.0.1:{sys.argv[1]}"
# The proxy refuses a handshake without SNI, and test.example does not resolve.
OPTIONS = {
    "headers": {"host": "test.example"},
    "extensions": {"sni_hostname": "test.example"},
}


def get(client, path):
    response = client.get(BASE + path, **OPTIONS)
    assert response.http_version == "HTTP/2", response.http_version
    return response.text


def say(line):
    print(line, flush=True)


idle = httpx.Client(http2=True, verify=False)
busy = httpx.Client(http2=True, verify=False)
say(get(idle, "/"))
say(get(busy, "/"))

slow = []
in_progress = threading.Thread(target=lambda: slow.append(get(busy, "/slow")))
in_progress.start()
sys.stdin.readline()
say(get(idle, "/"))
in_progress.join()
if not slow:
    sys.exit("the request in progress failed")
say(slow[0])
say(get(busy, "/"))
