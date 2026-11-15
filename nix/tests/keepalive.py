"""Sends GET / over one HTTPS keep-alive connection until STOP exists, and fails if the
connection is closed, replaced or answered with anything but 200. Prints how many requests
were answered before and after MARK appeared."""

import http.client
import os
import ssl
import sys
import time

host, mark, stop = sys.argv[1:4]

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

conn = http.client.HTTPSConnection(host, 443, context=context, timeout=5)
conn.connect()
sock = conn.sock
counts = {"before": 0, "after": 0}

while not os.path.exists(stop):
    conn.request("GET", "/")
    response = conn.getresponse()
    response.read()
    assert response.status == 200, f"status {response.status}"
    assert conn.sock is sock, "the connection was closed"
    counts["after" if os.path.exists(mark) else "before"] += 1
    time.sleep(0.05)

print(counts)
assert counts["before"] > 0 and counts["after"] > 0, counts
