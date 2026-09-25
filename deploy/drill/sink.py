"""Webhook sink for the alert drill.

Alertmanager POSTs its webhook payload to `/`; each firing alert's name is
recorded and printed. `GET /alerts` returns the names received so far as a
JSON list, which is what run.sh polls. Standard library only.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

received = []
lock = Lock()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        with lock:
            for alert in payload.get("alerts", []):
                if alert.get("status") == "firing":
                    name = alert.get("labels", {}).get("alertname", "")
                    received.append(name)
                    print(f"received {name} {alert.get('labels')}", flush=True)
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path != "/alerts":
            self.send_response(404)
            self.end_headers()
            return
        with lock:
            body = json.dumps(sorted(set(received))).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 9095), Handler).serve_forever()
