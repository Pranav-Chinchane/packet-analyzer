"""Engine tests on captures with known answers. Build first, then: python tests/run_tests.py"""
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.dont_write_bytecode = True
import generate_sample_traffic as demo
import generate_test_pcap as g

EXT = ".exe" if sys.platform == "win32" else ""
SAMPLE = ROOT / "data" / "test_dpi.pcap"
TEMP = tempfile.TemporaryDirectory()
TMP = Path(TEMP.name)
passed = failed = 0


def check(name, ok, info=""):
    global passed, failed
    passed, failed = passed + bool(ok), failed + (not ok)
    print(("PASS " if ok else "FAIL ") + name, "" if ok else info)


def run(program, *args):
    return subprocess.run([str(ROOT / "build" / (program + EXT)), *map(str, args)],
                          capture_output=True, text=True, timeout=120)


def engine(program, src, *args):
    """Runs a program; returns (process result, numbers in its report, output path)."""
    out = TMP / "out.pcap"
    out.unlink(missing_ok=True)
    r = run(program, src, out, *args)
    pairs = re.findall(r"^  ([\w ]+?) *: (\d+)$", r.stdout, re.M)
    pairs += re.findall(r"^  ([\w/ ]+?) +(\d+) +[\d.]+%", r.stdout, re.M)
    return r, {k: int(v) for k, v in pairs}, out


def packets(path):
    b, pos, out = path.read_bytes(), 24, []
    while pos < len(b):
        h = struct.unpack("<IIII", b[pos:pos + 16])
        out.append((h[3], b[pos + 16:pos + 16 + h[2]]))
        pos += 16 + h[2]
    return out


def make(name, pkts, **kw):
    p = TMP / name
    g.write_pcap(p, pkts, **kw)
    return p


DEMO = ROOT / "data" / "sample_traffic.pcap"


def pcapng(name, pkts, endian="<", nano=False):
    """Writes a .pcapng file with an unknown block that readers must skip."""
    def block(kind, body):
        body += b"\0" * (-len(body) % 4)
        size = struct.pack(endian + "I", len(body) + 12)
        return struct.pack(endian + "I", kind) + size + body + size
    option = struct.pack(endian + "HHB3xHH", 9, 1, 9, 0, 0) if nano else b""
    out = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack(endian + "HHI", 1, 0, 0) + option) + block(0x0BAD, b"skip")
    for i, p in enumerate(pkts):
        t = (1700000000 + i) * (10 ** 9 if nano else 10 ** 6)
        out += block(6, struct.pack(endian + "IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(p), len(p)) + p)
    (TMP / name).write_bytes(out)
    return TMP / name


g.write_pcap(SAMPLE, g.sample_packets())
demo.write(DEMO)
r = run("unit_tests", SAMPLE, TMP / "slow.pcap")
check("T4-T7, T16, T18 unit tests: " + r.stdout.strip().split("\n")[-1], r.returncode == 0, r.stdout)

T12 = ["--block-app", "youtube", "--block-domain", "FACEBOOK.com"]
T13 = T12 + ["--block-app", "TikTok", "--block-ip", g.BLOCKED]
U, S = g.USER, "1.2.3.4"
hello = g.client_hello("www.youtube.com")
reply = make("reply.pcap", [g.tcp(U, S, 50000, 443, g.PSH_ACK, hello), g.tcp(S, U, 443, 50000, g.ACK, b"data")])
eth = g.ROUTER_MAC + g.USER_MAC
other = make("other.pcap", [g.frame(U, S, 1, b"\x08" + b"\0" * 7), eth + b"\x86\xdd\x60" + b"\0" * 60,
                            eth + b"\x08\x06" + b"\0" * 28, g.tcp(U, S, 50000, 443, g.ACK)])
CASES = [("T10 no rules", SAMPLE, [], dict(Forwarded=77, Dropped=0, Flows=27, YouTube=4, Netflix=4, Microsoft=4, HTTPS=5, DNS=4)),
         ("T9 HTTP label", SAMPLE, [], dict(HTTP=4)),
         ("T11 block IP", SAMPLE, ["--block-ip", g.BLOCKED], dict(Forwarded=72, Dropped=5)),
         ("F8 block server IP", SAMPLE, ["--block-ip", "203.0.113.1"], dict(Forwarded=73, Dropped=4)),
         ("T12 app + domain", SAMPLE, T12, dict(Forwarded=74, Dropped=3)),
         ("T13 combined", SAMPLE, T13, dict(Forwarded=68, Dropped=9)),
         ("T14 reply blocked", reply, ["--block-app", "YouTube"], dict(Forwarded=0, Dropped=2)),
         ("T15 unsupported", other, [], dict(Forwarded=4, Dropped=0, Unsupported=3))]

hello6 = demo.Connection("fd00::5", "2001:db8::9", 50001)
six = make("six.pcap", hello6.handshake() + [hello6.send(0, g.PSH_ACK, hello)])
vlan = make("vlan.pcap", [p[:12] + b"\x81\x00\x00\x05" + p[12:] for p in g.sample_packets()])


def split(order):
    c = demo.Connection(U, S, 50002)
    c.seq[0] = 0xFFFFFFE0                        # sequence numbers wrap inside the message
    shake = c.handshake()
    parts = [c.send(0, g.ACK, hello[:30]), c.send(0, g.ACK, hello[30:70]), c.send(0, g.PSH_ACK, hello[70:])]
    return shake + [parts[i] for i in order]


YT = ["--block-app", "YouTube"]
CASES += [("IPv6 app rule", six, YT, dict(Forwarded=3, Dropped=1, YouTube=4)),
          ("IPv6 address rule", six, ["--block-ip", "2001:DB8:0::9"], dict(Forwarded=0, Dropped=4)),
          ("VLAN tags", vlan, YT, dict(Forwarded=76, Dropped=1, Flows=27)),
          ("split hello", make("s1.pcap", split([0, 1, 2])), YT, dict(Dropped=1, YouTube=6)),
          ("split hello out of order", make("s2.pcap", split([2, 1, 0])), YT, dict(Dropped=1, YouTube=6)),
          ("split hello repeated", make("s3.pcap", split([0, 0, 1, 1, 2])), YT, dict(Dropped=1, YouTube=8)),
          ("pcapng", pcapng("a.pcapng", g.sample_packets()), YT, dict(Forwarded=76, Dropped=1)),
          ("pcapng big-endian, nanoseconds", pcapng("b.pcapng", g.sample_packets(), ">", True), YT, dict(Forwarded=76, Dropped=1)),
          ("service labels", make("svc.pcap", [p for i, port in enumerate((22, 3389, 3306)) for c in [demo.Connection(U, S, 50100 + i, port)]
                                               for p in c.handshake()] + [g.udp(U, S, 50200, 123, b"x" * 48)]), [],
           {"SSH": 3, "Remote desktop": 3, "Database": 3, "NTP": 1, "Flows": 4}),
          ("block a service", TMP / "svc.pcap", ["--block-app", "remote desktop"], dict(Forwarded=8, Dropped=2)),
          ("demo capture", DEMO, T13, dict(Forwarded=489, Dropped=171, Flows=131))]

for program in ("dpi_simple", "dpi_mt"):
    _, _, out = engine(program, pcapng("c.pcapng", g.sample_packets(), ">", True))
    check(f"pcapng times and bytes kept [{program}]", sorted(out.read_bytes()[24:]) == sorted(SAMPLE.read_bytes()[24:]))
    r, _, _ = engine(program, DEMO)
    check(f"alerts found [{program}]", all(a in r.stdout for a in ("Possible port scan: 192.168.1.50 tried 18 ports on 192.168.1.10",
          "Unusual DNS activity: 192.168.1.13 looked up 14", "Unencrypted web traffic", "6 devices on the local network")))
    r, _, _ = engine(program, SAMPLE)
    check(f"no false scan or DNS alert [{program}]", "Possible" not in r.stdout and "Unusual" not in r.stdout)
    for name, src, args, want in CASES:
        r, got, out = engine(program, src, *args)
        ok = r.returncode == 0 and all(got.get(k) == v for k, v in want.items())
        ok = ok and (src == DEMO or "Other" not in got) and len(packets(out)) == got["Forwarded"]
        check(f"{name} [{program}]", ok, f"got {got} {r.stderr}")

    _, _, out = engine(program, make("be.pcap", g.sample_packets(), endian=">"))
    check(f"T1 byte order [{program}]", sorted(packets(out)) == sorted(packets(SAMPLE)))
    _, _, out = engine(program, make("orig.pcap", g.sample_packets(), original_len=9999))
    check(f"T2 original length [{program}]", len(packets(out)) == 77 and all(p[0] == 9999 for p in packets(out)))

    (TMP / "empty.pcap").write_bytes(b"")
    (TMP / "ng.pcap").write_bytes(struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28) + struct.pack("<II", 6, 999))
    for bad in ("empty.pcap", "ng.pcap", "missing.pcap"):
        r, _, _ = engine(program, TMP / bad)
        check(f"T3 {bad} [{program}]", r.returncode == 1 and "Error" in r.stderr, r)
    (TMP / "cut.pcap").write_bytes(SAMPLE.read_bytes()[:-10])
    r, _, out = engine(program, TMP / "cut.pcap")
    check(f"T3 truncated [{program}]", r.returncode == 1 and "truncated" in r.stderr and len(packets(out)) == 76, r)
    same_file = make("same.pcap", g.sample_packets())
    before = same_file.read_bytes()
    r = run(program, same_file, same_file)
    check(f"F14 same file refused [{program}]", r.returncode == 1 and same_file.read_bytes() == before)

r, _, out = engine("dpi_simple", SAMPLE)
check("T8 all names found", all(f"  {n} -> " in r.stdout for n in g.SITES + g.HTTP_HOSTS + g.DNS_NAMES))
check("N4 no-rule output identical to input", out.read_bytes() == SAMPLE.read_bytes())
for bad in (["--lbs", "0"], ["--lbs", "-1"], ["--lbs", "abc"], ["--fps", "65"], ["--fps"], ["--what", "1"], ["--block-ip", "1.2"]):
    r, _, _ = engine("dpi_mt", SAMPLE, *bad)
    check("T19 rejects " + " ".join(bad), r.returncode == 1 and r.stderr.startswith("Error"), r)
_, got, _ = engine("dpi_mt", SAMPLE)
work = [got.get(f"Worker {i} packets", 0) for i in range(4)]
check(f"T19 all workers busy {work}", all(work))

for program in ("dpi_simple", "dpi_mt"):
    js = TMP / "r.json"
    _, got, _ = engine(program, SAMPLE, *T13, "--json", js)
    data = json.loads(js.read_text())
    check(f"JSON report [{program}]", data["forwarded"] == 68 and data["dropped"] == 9 and data["apps"]["YouTube"] == 4
          and data["names"]["www.netflix.com"] == "Netflix" and sum(data["blocked"].values()) == 9
          and sum(data["appsDropped"].values()) == 9 and data["appsDropped"]["YouTube"] == 1, data)
    for src in (SAMPLE, DEMO):
        engine(program, src, "--json", js)
        data = json.loads(js.read_text())
        slots = data["timeline"]["slots"]
        check(f"JSON details {src.name} [{program}]", sum(a + b for a, b in slots) == data["total"] and len(slots) <= 60
              and sum(c["packets"] for c in data["connections"]) == data["total"] - data["unsupported"] and data["summary"])
    r, _, out = engine(program, SAMPLE, "--json", TMP / "out.pcap")
    check(f"JSON over output refused [{program}]", r.returncode == 1 and not out.exists())


# ---- summary and alerts ----
def insights(pkts, *args, times=None):
    src = make("ins.pcap", pkts, times=times)
    reports = []
    for program in ("dpi_simple", "dpi_mt"):
        engine(program, src, *args, "--json", TMP / "ins.json")
        d = json.loads((TMP / "ins.json").read_text())
        reports.append((d["summary"], [(a["title"], a["detail"], a["warning"]) for a in d["alerts"]], d["devices"]))
    check("  engines agree", reports[0] == reports[1], reports)
    return reports[0]


def syns(n, vary, src="192.168.1.9"):
    return [g.tcp(src, f"198.51.100.{i + 1}" if vary == "host" else S, 40000 + i, 445 if vary == "host" else 1000 + i, g.SYN) for i in range(n)]


def lookups(n, name, src="192.168.1.9"):
    return [g.udp(src, g.RESOLVER, 41000 + i, 53, g.dns_query(name(i))) for i in range(n)]


def titles(pkts, *args):
    return [a[0] for a in insights(pkts, *args)[1]]


def long_name(i):
    return f"{i:02d}" + "a" * 28 + ".evil.com"        # 30 characters before the domain


for name, pkts, want in [
        ("14 ports", syns(14, "port"), []), ("15 ports", syns(15, "port"), ["Possible port scan"]),
        ("19 hosts", syns(19, "host"), []), ("20 hosts", syns(20, "host"), ["Possible network scan"]),
        ("20 answered hosts", [p for i in range(20) for p in demo.Connection(U, f"198.51.100.{i + 1}", 42000 + i, 445).handshake()], []),
        ("9 long names", lookups(9, long_name), []), ("10 long names", lookups(10, long_name), ["Unusual DNS activity"]),
        ("same long name repeated", lookups(30, lambda i: long_name(1)), []),
        ("30 short names", lookups(30, lambda i: f"s{i}.example.com"), []),
        ("long names from different machines", [p for i in range(12) for p in lookups(1, lambda _: long_name(i), f"192.168.1.{i + 1}")], []),
        ("reverse lookups", lookups(30, lambda i: ".".join(f"{i:032x}"[::-1]) + ".ip6.arpa"), []),
        ("FTP used", demo.Connection(U, S, 43000, 21).handshake(), ["Unencrypted login protocol"]),
        ("Telnet used", demo.Connection(U, S, 43000, 23).handshake(), ["Unencrypted login protocol"]),
        ("FTP not answered", [g.tcp(U, S, 43000, 21, g.SYN)], []),
        ("HTTP", [g.tcp(U, S, 43000, 80, g.PSH_ACK, g.http_get("plain.com"))], ["Unencrypted web traffic"]),
        ("HTTPS", [g.tcp(U, S, 43000, 443, g.PSH_ACK, hello)], []),
        ("replies only, capture started late", [g.tcp(S, U, 8443, 44000 + i, g.ACK, b"data") for i in range(40)], []),
        ("QUIC to many machines", [g.udp(U, f"198.51.100.{i + 1}", 45000 + i, 443, b"x" * 50) for i in range(40)], [])]:
    check(f"alert: {name}", titles(pkts) == want, titles(pkts))
check("alert survives blocking", titles(syns(15, "port"), "--block-ip", "192.168.1.9") == ["Possible port scan"])
check("alert survives app blocking", titles(demo.Connection(U, S, 43000, 23).handshake(), "--block-app", "Telnet") == ["Unencrypted login protocol"])
_, a, _ = insights([g.tcp(U, S, 43000 + i, 80, g.PSH_ACK, g.http_get(f"p{i}.com")) for i in range(5)])
check("alert lists sites", a[0][1] == "Others on the network can read traffic to p0.com, p1.com, p2.com and 2 more." and not a[0][2], a)
check("alert of every kind together", sorted(titles(syns(15, "port") + syns(20, "host", "192.168.1.8") + lookups(10, long_name) + demo.Connection(U, S, 43000, 21).handshake()
      + [g.tcp(U, S, 43001, 80, g.PSH_ACK, g.http_get("a.com"))])) == ["Possible network scan", "Possible port scan", "Unencrypted login protocol", "Unencrypted web traffic", "Unusual DNS activity"])

one = [g.tcp(U, S, 50000, 443, g.SYN)]
check("summary: one packet", insights(one)[0] == ["1 packet in 1 connection within one second.", "HTTPS made up the most traffic: 100.0% of packets.",
      f"1 device on the local network. The busiest was {U}.", "Nothing was blocked."], insights(one)[0])
for gap, text in [(1, "1 second"), (59, "59 seconds"), (60, "1 minute"), (61, "1 minute 1 second"), (3600, "1 hour"), (7320, "2 hours 2 minutes")]:
    check(f"summary: {text}", insights(one * 2, times=[1000, 1000 + gap])[0][0] == f"2 packets in 1 connection over {text}.")
check("summary: times out of order", insights(one * 2, times=[1061, 1000])[0][0].endswith("over 1 minute 1 second."))
check("summary: empty capture", insights([]) == (["The capture is empty."], [], []))
check("summary: no local devices", len(insights([g.tcp("9.9.9.9", S, 50000, 443, g.SYN)])[0]) == 3)
check("summary: only unsupported packets", insights([eth + b"\x08\x06" + bytes(28)])[0] == ["1 packet in 0 connections within one second.", "Nothing was blocked."])
check("summary: blocked share", insights(one * 3 + [g.tcp(U, S, 50001, 80, g.SYN)], "--block-app", "HTTPS")[0][-1] == "Your rules blocked 3 packets (75.0%).")

js_a, js_b = TMP / "a.json", TMP / "b.json"
engine("dpi_simple", DEMO, *T13, "--json", js_a)
engine("dpi_mt", DEMO, *T13, "--json", js_b)
a, b = json.loads(js_a.read_text()), json.loads(js_b.read_text())
a.pop("workers"), b.pop("workers")
check("whole JSON report identical in both engines", a == b)

baseline = {n: engine("dpi_simple", s, *a)[1] for n, s, a, _ in CASES}
same = True
for i in range(100):
    for n, s, a, _ in CASES:
        got = engine("dpi_mt", s, *a, "--lbs", 1 + i % 4, "--fps", 1 + i % 3)[1]
        same = same and {k: v for k, v in got.items() if "Worker" not in k} == baseline[n]
check("T17 multi-threaded equals simple, 100 runs of every case", same and all(baseline.values()))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
