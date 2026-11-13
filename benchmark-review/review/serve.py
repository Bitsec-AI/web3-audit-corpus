"""Serve the ground-truth review app and save labels next to this file (labels.json, or labels_<set>.json per dataset).

    .venv/bin/python -I benchmark-review/review/serve.py [--port 8765]
"""
import argparse
import json
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent


def labels_path(path):
    """labels.json for the starter set, labels_<set>.json for other datasets (?set=<name>)."""
    name = (parse_qs(urlparse(path).query).get("set") or ["findings"])[0]
    return HERE / ("labels.json" if name == "findings" else f"labels_{''.join(ch for ch in name if ch.isalnum() or ch == '_')}.json")


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(HERE), **kw)

    def send_json(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.split("?")[0] == "/api/labels":
            path = labels_path(self.path)
            return self.send_json(json.loads(path.read_text()) if path.exists() else {})
        return super().do_GET()

    def do_POST(self):
        if self.path.split("?")[0] != "/api/labels":
            return self.send_json({"error": "not found"}, 404)
        labels = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        path = labels_path(self.path)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(labels, indent=1))
        os.replace(tmp, path)
        self.send_json({"saved": len(labels)})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    print(f"http://127.0.0.1:{args.port}/", flush=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
