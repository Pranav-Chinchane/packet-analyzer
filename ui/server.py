"""Local web UI. Start: python ui/server.py   then open http://127.0.0.1:8000

Standard library only. Reachable only from this computer. Uploaded captures
live in a temporary folder that is deleted when the server stops.
"""
import json
import secrets
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
EXT = ".exe" if sys.platform == "win32" else ""
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
MAX_UPLOAD = 200 * 1024 * 1024
KEEP_RESULTS = 5
MAX_RULES = 8000             # characters; keeps the command line within OS limits
STATIC = {"/icons.js": "text/javascript", "/fonts/schibsted-grotesk.woff2": "font/woff2"}
OPTIONS = {"app": "--block-app", "domain": "--block-domain", "ip": "--block-ip"}

temp = tempfile.TemporaryDirectory(prefix="dpi_ui_")
results = []                    # ids of filtered files that can be downloaded
lock = threading.Lock()


def analyze(query, capture):
    """Returns (HTTP status, response dict)."""
    engine = query.get("engine", ["simple"])[0]
    if engine not in ("simple", "mt"):
        return 400, {"error": "unknown engine"}
    program = ROOT / "build" / f"dpi_{engine}{EXT}"
    if not program.exists():
        return 500, {"error": "Engine not built. Run build.ps1 first."}

    rid = secrets.token_hex(8)
    base = Path(temp.name) / rid
    src, out, report = base.with_suffix(".in"), base.with_suffix(".pcap"), base.with_suffix(".json")
    cmd = [str(program), str(src), str(out), "--json", str(report)]
    for key, flag in OPTIONS.items():
        for value in query.get(key, []):
            cmd += [flag, value]
    if sum(len(v) for k in OPTIONS for v in query.get(k, [])) > MAX_RULES:
        return 400, {"error": "Too many block rules."}
    if "\0" in "".join(cmd):
        return 400, {"error": "invalid rule"}
    try:
        src.write_bytes(capture)
        run = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=120)
        message = run.stderr.strip().removeprefix("Error: ")
        if not report.exists():
            out.unlink(missing_ok=True)
            return 400, {"error": message or "invalid input"}
        data = json.loads(report.read_text())
    except OSError:
        out.unlink(missing_ok=True)
        return 500, {"error": "The engine could not be run."}
    except subprocess.TimeoutExpired:
        out.unlink(missing_ok=True)
        return 500, {"error": "analysis took too long"}
    finally:
        src.unlink(missing_ok=True)
        report.unlink(missing_ok=True)
    data.update(id=rid, warning=message)
    with lock:
        results.append(rid)
        while len(results) > KEEP_RESULTS:
            (Path(temp.name) / (results.pop(0) + ".pcap")).unlink(missing_ok=True)
    return 200, data


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # On Windows, address reuse would let two servers share one port.
    allow_reuse_address = sys.platform != "win32"


class Handler(BaseHTTPRequestHandler):
    timeout = 60

    def send(self, status, body, kind, extra=()):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, data):
        self.send(status, json.dumps(data).encode(), "application/json")

    def allowed(self):
        # Stops other websites from driving this server through the browser.
        origin = self.headers.get("Origin")
        if self.headers.get("Host") in HOSTS and (origin is None or urlsplit(origin).netloc in HOSTS):
            return True
        self.close_connection = True
        self.send_json(403, {"error": "forbidden"})
        return False

    def do_GET(self):
        if not self.allowed():
            return
        path = urlsplit(self.path).path
        if path == "/":
            csp = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                   "connect-src 'self'; font-src 'self'; img-src data:")
            self.send(200, (ROOT / "ui" / "index.html").read_bytes(), "text/html; charset=utf-8",
                      [("Content-Security-Policy", csp)])
        elif path in STATIC:
            self.send(200, (ROOT / "ui" / path[1:]).read_bytes(), STATIC[path])
        elif path == "/api/sample" and (ROOT / "data" / "sample_traffic.pcap").exists():
            self.send(200, (ROOT / "data" / "sample_traffic.pcap").read_bytes(), "application/octet-stream")
        elif path.startswith("/api/download/") and path.rsplit("/", 1)[1] in results:
            file = Path(temp.name) / (path.rsplit("/", 1)[1] + ".pcap")
            try:
                body = file.read_bytes()
            except OSError:                  # replaced by newer results meanwhile
                return self.send_json(404, {"error": "not found"})
            self.send(200, body, "application/octet-stream",
                      [("Content-Disposition", 'attachment; filename="filtered.pcap"')])
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if not self.allowed():
            return
        url = urlsplit(self.path)
        if url.path != "/api/analyze":
            self.close_connection = True
            return self.send_json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_UPLOAD:
            self.close_connection = True
            return self.send_json(413, {"error": "File must not be empty or larger than 200 MB."})
        capture = self.rfile.read(length)
        if len(capture) != length:
            self.close_connection = True
            return self.send_json(400, {"error": "The upload was interrupted."})
        self.send_json(*analyze(parse_qs(url.query), capture))

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    try:
        server = Server(("127.0.0.1", PORT), Handler)
    except OSError:
        sys.exit(f"Port {PORT} is already in use. Stop the other server or run: python ui/server.py 8080")
    print(f"Open http://127.0.0.1:{PORT}  (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        temp.cleanup()
