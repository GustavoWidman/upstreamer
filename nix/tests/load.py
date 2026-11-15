"""Requests URL on a new connection after another until STOP exists, trusting CA, and fails if
any request was not answered with 200. Prints the number of requests answered."""

import os
import ssl
import sys
import urllib.request

url, ca, stop = sys.argv[1:4]

context = ssl.create_default_context(cafile=ca)
answered = 0
failures = []

while not os.path.exists(stop):
    try:
        with urllib.request.urlopen(url, context=context, timeout=5) as response:
            response.read()
            answered += 1
    except Exception as error:
        failures.append(repr(error))

print({"answered": answered, "failures": failures})
assert answered > 0 and not failures
