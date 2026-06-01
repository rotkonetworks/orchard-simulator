#!/usr/bin/env python3
"""Static file server with no-cache headers so iterating on JS/HTML/CSS
doesn't leave the browser stuck on a stale build.

Usage: from `web/` directory, `python3 serve.py [port]` (default 8000).
"""
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler


class NoCacheHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        # Security headers that browsers ignore in <meta http-equiv> form.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # Cross-origin isolation. Enables SharedArrayBuffer so the
        # parallel-WASM build (web/pkg-parallel/) can spin up a rayon
        # thread pool. Harmless for the single-threaded build because
        # the page only loads same-origin resources anyway.
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
            "worker-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'",
        )
        super().end_headers()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    addr = ("127.0.0.1", port)
    print(f"Serving with no-cache headers on http://{addr[0]}:{addr[1]}/", flush=True)
    HTTPServer(addr, NoCacheHandler).serve_forever()
