"""Stands in for heimdall's API on 127.0.0.1:7979: /api/health, /api/login (password hunter2,
sets a session cookie) and /api/sync (needs the cookie; answers the epoch and the ops it was
sent)."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EPOCH = "e-7f3a"
SESSION = "session=s3cr3t"


class Api(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, status, body, headers=()):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/health":
            self.reply(200, {"ok": True})
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path == "/api/login" and body.get("password") == "hunter2":
            self.reply(200, {}, [("Set-Cookie", f"{SESSION}; Path=/; HttpOnly")])
        elif self.path == "/api/sync" and self.headers.get("Cookie") == SESSION:
            ops = [{"seq": i + 1, "op": op} for i, op in enumerate(body.get("ops", []))]
            self.reply(200, {"epoch": EPOCH, "head": len(ops), "ops": ops})
        else:
            self.reply(401, {"error": "unauthorized"})


ThreadingHTTPServer(("127.0.0.1", 7979), Api).serve_forever()
