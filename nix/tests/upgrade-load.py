"""Clients for the upgrade test. Each prints one JSON object when it ends.

connect HOST PORT STOP, get FLAG URL CA STOP, keep URL CA STOP and batch FLAG URL CA STOP run
until the file STOP exists and print how many attempts ended in each outcome, and when the
first and the last attempt that did not succeed started (seconds since the epoch):
- connect opens a TCP connection and closes it. Outcomes: connected, refused, timeout, or the
  error.
- get runs one `curl FLAG` per request, so a new connection each. Outcomes: the status, or
  curl's exit code.
- keep sends requests on one HTTP/1.1 connection, replaced when the server says it closes it.
  Outcomes: the status, or the error.
- batch runs `curl FLAG` with fifty requests at a time, which curl sends one after another on
  one connection, opening another when the server ends that one (GOAWAY over HTTP/2 and
  HTTP/3). Outcomes: the status, or curl's exit code for the request.

idle URL CA sends a request every two seconds on one HTTP/1.1 connection, which is idle in
between, until the server says it closes the connection or closes it without saying. It prints
the last response's status, whether it announced the close, and how many requests were
answered; or the error."""

import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

mode, *args = sys.argv[1:]


class Tally:
    def __init__(self, good):
        self.good = good
        self.counts = {}
        self.failures = []

    def record(self, outcome, started):
        self.counts[outcome] = self.counts.get(outcome, 0) + 1
        if outcome != self.good:
            self.failures.append(started)

    def result(self):
        return {
            "counts": self.counts,
            "first_failure": min(self.failures, default=None),
            "last_failure": max(self.failures, default=None),
        }


def connect(host, port, stop):
    tally = Tally("connected")
    while not os.path.exists(stop):
        started = time.time()
        try:
            socket.create_connection((host, int(port)), timeout=3).close()
            outcome = "connected"
        except ConnectionRefusedError:
            outcome = "refused"
        except TimeoutError:
            outcome = "timeout"
        except OSError as error:
            outcome = repr(error)
        tally.record(outcome, started)
        # Often enough to meet any gap, and few enough connections for the firewall to track.
        time.sleep(0.02)
    return tally.result()


def get(flag, url, ca, stop):
    tally = Tally("200")
    command = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--cacert", ca]
    command += ["--connect-timeout", "5", "--max-time", "10", flag, url]
    while not os.path.exists(stop):
        started = time.time()
        done = subprocess.run(command, capture_output=True, text=True)
        outcome = done.stdout if done.returncode == 0 else f"curl exit {done.returncode}"
        tally.record(outcome, started)
    return tally.result()


def connection(url, ca):
    target = urllib.parse.urlsplit(url)
    context = ssl.create_default_context(cafile=ca)
    return target, http.client.HTTPSConnection(target.netloc, context=context, timeout=10)


def keep(url, ca, stop):
    tally = Tally("200")
    conn = None
    while not os.path.exists(stop):
        started = time.time()
        try:
            if conn is None:
                target, conn = connection(url, ca)
            conn.request("GET", target.path)
            response = conn.getresponse()
            response.read()
            outcome = str(response.status)
            if response.will_close:
                conn.close()
                conn = None
        except (OSError, http.client.HTTPException) as error:
            outcome = repr(error)
            conn = None
        tally.record(outcome, started)
    return tally.result()


def batch(flag, url, ca, stop):
    tally = Tally("200")
    command = ["curl", "-s", "-w", "%{http_code} %{exitcode}\n", "--cacert", ca]
    command += ["--connect-timeout", "5", "--max-time", "10", flag]
    for _ in range(50):
        command += ["-o", "/dev/null", url]
    while not os.path.exists(stop):
        started = time.time()
        done = subprocess.run(command, capture_output=True, text=True)
        for line in done.stdout.splitlines():
            status, code = line.split()
            tally.record(status if code == "0" else f"curl exit {code}", started)
    return tally.result()


def idle(url, ca):
    target, conn = connection(url, ca)
    answered = 0
    while True:
        try:
            conn.request("GET", target.path)
            response = conn.getresponse()
            response.read()
        except (OSError, http.client.HTTPException) as error:
            return {"error": repr(error), "answered": answered}
        answered += 1
        if response.status != 200 or response.will_close:
            return {"status": response.status, "closes": response.will_close, "answered": answered}
        time.sleep(2)


modes = {"connect": connect, "get": get, "keep": keep, "batch": batch, "idle": idle}
print(json.dumps(modes[mode](*args)))
