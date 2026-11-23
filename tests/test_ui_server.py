"""Tests the web server. Build first, then: python tests/test_ui_server.py"""
import http.client
import json
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = (ROOT / "data" / "sample_traffic.pcap").read_bytes()
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    PORT = s.getsockname()[1]
failed = 0


def check(name, ok):
    global failed
    failed += not ok
    print(("PASS " if ok else "FAIL ") + name)


def call(method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    c.request(method, path, body, headers or {})
    r = c.getresponse()
    return r.status, r.read()


def start():
    return subprocess.Popen([sys.executable, str(ROOT / "ui" / "server.py"), str(PORT)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


server = start()
try:
    server.stdout.readline()
    for path in ("/icons.js", "/fonts/schibsted-grotesk.woff2"):
        check("serves " + path, call("GET", path)[0] == 200)
    check("page loads", call("GET", "/")[0] == 200)
    check("sample loads", call("GET", "/api/sample") == (200, SAMPLE))
    for engine in ("simple", "mt"):
        code, body = call("POST", f"/api/analyze?engine={engine}&app=YouTube&domain=facebook.com&ip=192.168.1.50", SAMPLE)
        d = json.loads(body)
        check(f"analysis [{engine}]", code == 200 and (d["total"], d["forwarded"], d["dropped"], d["flows"]) == (660, 503, 157, 131))
        code, out = call("GET", "/api/download/" + d["id"])
        check(f"filtered file [{engine}]", code == 200 and 24 < len(out) < len(SAMPLE))
    for name, path, body in [("bad IP", "ip=bad", SAMPLE), ("bad app", "app=nope", SAMPLE), ("bad engine", "engine=x", SAMPLE),
                             ("option as value", "domain=--help", SAMPLE), ("NUL", "domain=a%00", SAMPLE),
                             ("non-ASCII", "domain=%E4%B8%AD", SAMPLE), ("not a capture", "", b"junk"),
                             ("too many rules", "&".join(f"domain=site{i}.com" for i in range(1000)), SAMPLE)]:
        code, out = call("POST", "/api/analyze?" + path, body)
        check("rejects " + name, code == 400 and "error" in json.loads(out))
    check("rejects empty upload", call("POST", "/api/analyze", b"")[0] == 413)
    code, out = call("POST", "/api/analyze", SAMPLE[:-5])
    check("warns on truncated capture", code == 200 and "truncated" in json.loads(out)["warning"])
    with socket.create_connection(("127.0.0.1", PORT), timeout=10) as s:
        s.sendall(f"POST /api/analyze HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nContent-Length: 9999\r\n\r\nabc".encode())
        s.shutdown(socket.SHUT_WR)
        check("rejects interrupted upload", b" 400 " in s.recv(200))
    check("rejects foreign Host", call("GET", "/", headers={"Host": "evil.com"})[0] == 403)
    check("rejects foreign Origin", call("POST", "/api/analyze", SAMPLE, {"Origin": "http://evil.com"})[0] == 403)
    check("no path traversal", call("GET", "/api/download/../../README.md")[0] == 404)
    second = start()
    _, err = second.communicate(timeout=20)
    check("port in use is reported", second.returncode == 1 and "already in use" in err)
finally:
    server.kill()
print(f"{failed} failed")
sys.exit(1 if failed else 0)
