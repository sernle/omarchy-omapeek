#!/usr/bin/env python3
"""
OmaPeek macOS Mock Runner Server.
Simulates Omarchy Quattro's Quickshell desktop & OmaPeek overlay locally in your browser.
Uses the exact same `bin/omapeek-inspect.py` engine that runs on Arch Linux / Omarchy.
"""

from __future__ import annotations

import argparse
from email.parser import BytesParser
from email.policy import default as email_default_policy
import json
import mimetypes
import subprocess
import sys
import tempfile
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT_DIR / "samples"
MOCK_DIR = Path(__file__).resolve().parent
RUST_BIN = ROOT_DIR / "bin" / "omapeek-inspect"
UPLOAD_DIR = Path(tempfile.gettempdir()) / "omapeek-mock-uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(ROOT_DIR / "bin"))
import importlib.util

_spec = importlib.util.spec_from_file_location("omapeek_inspect", ROOT_DIR / "bin" / "omapeek-inspect.py")
assert _spec and _spec.loader
omapeek_inspect = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(omapeek_inspect)


def run_inspector(target: str) -> dict:
    """Prefer the native Rust binary (`bin/omapeek-inspect`); fall back to Python."""
    if RUST_BIN.exists():
        proc = subprocess.run([str(RUST_BIN), target], capture_output=True, text=True)
        if proc.returncode != 0:
            err = proc.stderr.strip() or f"Inspector exited with code {proc.returncode}"
            raise RuntimeError(err)
        return json.loads(proc.stdout)
    return omapeek_inspect.inspect_file(target)


class OmaPeekHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return  # Keep terminal output clean

    def _send_json(self, payload: dict, status: int = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/api/health":
            self._send_json({"ok": True})
            return

        if parsed.path == "/api/samples":
            samples = []
            if SAMPLES_DIR.exists():
                for p in sorted(SAMPLES_DIR.iterdir()):
                    if p.is_file() and not p.name.startswith("."):
                        samples.append({"name": p.name, "path": str(p)})
            self._send_json({"samples": samples})
            return

        if parsed.path == "/api/inspect":
            target = qs.get("path", [""])[0]
            if not target:
                self._send_json({"error": "Missing `path` query parameter"}, HTTPStatus.BAD_REQUEST)
                return
            try:
                result = run_inspector(target)
                self._send_json(result)
            except Exception as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if parsed.path == "/api/raw":
            target = qs.get("path", [""])[0]
            p = Path(target).expanduser().resolve()
            if not p.exists() or not p.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "File not found")
                return
            mime, _ = mimetypes.guess_type(str(p))
            data = p.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mime or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if parsed.path in ("/", "/index.html"):
            html = (MOCK_DIR / "index.html").read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/upload":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_json({"error": "Expected multipart/form-data"}, HTTPStatus.BAD_REQUEST)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        raw_msg = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
        msg = BytesParser(policy=email_default_policy).parsebytes(raw_msg)

        file_name = None
        file_bytes = None
        if msg.is_multipart():
            for part in msg.iter_parts():
                if part.get_param("name", header="content-disposition") == "file":
                    file_name = part.get_filename()
                    file_bytes = part.get_payload(decode=True)
                    break

        if not file_name or file_bytes is None:
            self._send_json({"error": "No file uploaded"}, HTTPStatus.BAD_REQUEST)
            return

        safe_name = Path(file_name).name
        dest = UPLOAD_DIR / safe_name
        dest.write_bytes(file_bytes)
        try:
            result = run_inspector(str(dest))
            self._send_json(result)
        except Exception as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def main() -> None:
    parser = argparse.ArgumentParser(description="OmaPeek macOS Mock Runner")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4173)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), OmaPeekHandler)
    print(f"OmaPeek mock runner listening at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down OmaPeek mock runner.")


if __name__ == "__main__":
    main()
