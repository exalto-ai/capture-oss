#!/usr/bin/env python3
"""Loopback-only hosted Trace fixture for the daemon persistence E2E."""

import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


API_KEY = "notary_key_" + "1" * 32 + "_" + "2" * 64
PUBLIC_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
KEY_ID = "sha256:0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    traces: dict[str, dict[str, object]] = {}
    last_trace_id = ""

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.respond_json({"status": "ready"})
            return
        if self.path == "/debug/upload":
            trace = type(self).traces.get(type(self).last_trace_id, {})
            uploaded = trace.get("uploaded", b"")
            assert isinstance(uploaded, bytes)
            self.respond_json(
                {
                    "size_bytes": len(uploaded),
                    "sha256": hashlib.sha256(uploaded).hexdigest(),
                }
            )
            return
        if self.path == "/api/registry":
            self.respond_json(
                {
                    "format": "ecp/registry/v1",
                    "generation": 1,
                    "active_key_id": KEY_ID,
                    "notaries": [
                        {
                            "name": "E2E Notary",
                            "operator": "Exalto",
                            "host": "notary",
                            "port": 7047,
                            "transport": "tcp",
                            "key_id": KEY_ID,
                            "verification_key": PUBLIC_KEY,
                            "status": "active",
                            "valid_from_unix_ms": 0,
                            "valid_until_unix_ms": None,
                            "notarize_until_unix_ms": None,
                        }
                    ],
                }
            )
            return
        if self.path.startswith("/api/traces/"):
            if not self.authorized():
                return
            trace_id = self.path.removeprefix("/api/traces/")
            if trace_id not in type(self).traces:
                self.send_error(404)
                return
            self.respond_json(self.trace(trace_id, "verifying"))
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if not self.authorized():
            return
        if self.path == "/api/traces":
            request = json.loads(self.read_body())
            if request.get("package_format") != "ecp/trace-package/v1":
                self.send_error(400)
                return
            trace_id = f"trc-e2e-{request['package_sha256'][:16]}"
            type(self).traces[trace_id] = {
                "expected_size": int(request["package_size_bytes"]),
                "expected_sha256": request["package_sha256"],
                "uploaded": b"",
            }
            type(self).last_trace_id = trace_id
            self.respond_json(
                {
                    "trace": self.trace(trace_id, "verifying"),
                    "upload": {
                        "method": "PUT",
                        "url": f"http://127.0.0.1:9797/upload/{trace_id}",
                        "headers": {
                            "content-length": str(request["package_size_bytes"]),
                            "content-type": "application/vnd.exalto.notary.trace-package+zip",
                        },
                    },
                },
                status=201,
            )
            return
        if self.path.startswith("/api/traces/") and self.path.endswith(
            "/upload-completion"
        ):
            trace_id = self.path.removeprefix("/api/traces/").removesuffix(
                "/upload-completion"
            )
            trace = type(self).traces.get(trace_id)
            if trace is None:
                self.send_error(404)
                return
            request = json.loads(self.read_body())
            uploaded = trace["uploaded"]
            assert isinstance(uploaded, bytes)
            if (
                request.get("package_size_bytes") != trace["expected_size"]
                or request.get("package_sha256") != trace["expected_sha256"]
                or len(uploaded) != trace["expected_size"]
                or hashlib.sha256(uploaded).hexdigest() != trace["expected_sha256"]
            ):
                self.send_error(409)
                return
            self.respond_json(self.trace(trace_id, "verifying"))
            return
        self.send_error(404)

    def do_PUT(self) -> None:
        if not self.path.startswith("/upload/"):
            self.send_error(404)
            return
        trace_id = self.path.removeprefix("/upload/")
        trace = type(self).traces.get(trace_id)
        if trace is None:
            self.send_error(404)
            return
        trace["uploaded"] = self.read_body()
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def authorized(self) -> bool:
        if self.headers.get("Authorization") == f"Bearer {API_KEY}":
            return True
        self.send_error(401)
        return False

    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    @staticmethod
    def trace(trace_id: str, status: str) -> dict[str, object]:
        return {
            "trace_id": trace_id,
            "status": status,
            "access": {
                "visibility": "unlisted",
                "password_protected": False,
                "expires_at": None,
            },
            "verification": {"failure_code": None},
            "status_url": f"/api/traces/{trace_id}",
            "public_url": None,
            "package_url": None,
        }

    def respond_json(self, value: object, status: int = 200) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, message: str, *args: object) -> None:
        print(f"share fixture: {message % args}", flush=True)


def main() -> None:
    ThreadingHTTPServer(("127.0.0.1", 9797), Handler).serve_forever()


if __name__ == "__main__":
    main()
