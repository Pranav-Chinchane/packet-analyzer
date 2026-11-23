"""Creates data/sample_traffic.pcap: a larger synthetic capture for demos."""
import ipaddress
import struct
from pathlib import Path
import generate_test_pcap as g

# host, connections, data packets per connection
TRAFFIC = [("www.youtube.com", 6, 14), ("i.ytimg.com", 3, 6), ("www.netflix.com", 3, 18), ("www.google.com", 6, 5),
           ("www.instagram.com", 4, 7), ("www.facebook.com", 4, 5), ("github.com", 4, 6), ("web.whatsapp.com", 3, 6),
           ("open.spotify.com", 2, 9), ("www.microsoft.com", 3, 4), ("zoom.us", 1, 14), ("www.amazon.in", 2, 5),
           ("x.com", 2, 4), ("www.tiktok.com", 2, 6), ("discord.com", 1, 5), ("news.example.org", 2, 4)]


def frame6(src, dst, proto, body):
    addr = ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
    return g.ROUTER_MAC + g.USER_MAC + b"\x86\xdd" + struct.pack(">IHBB", 6 << 28, len(body), proto, 64) + addr + body


def tcp(src, dst, sport, dport, flags, payload, seq, ack):
    if ":" not in src:
        return g.tcp(src, dst, sport, dport, flags, payload, seq, ack)
    return frame6(src, dst, 6, struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload)


class Connection:
    """Keeps correct TCP sequence numbers for both sides."""

    def __init__(self, user, server, port, server_port=443):
        self.ends, self.ports = (user, server), (port, server_port)
        self.seq = [g.rng.randrange(1 << 32), g.rng.randrange(1 << 32)]

    def send(self, side, flags, payload=b""):
        other = 1 - side
        p = tcp(self.ends[side], self.ends[other], self.ports[side], self.ports[other], flags, payload,
                self.seq[side], self.seq[other] if flags & g.ACK else 0)
        self.seq[side] = (self.seq[side] + len(payload) + (1 if flags & g.SYN else 0)) % (1 << 32)
        return p

    def handshake(self):
        return [self.send(0, g.SYN), self.send(1, g.SYN_ACK), self.send(0, g.ACK)]


def build():
    g.rng.seed(7)
    sessions, port = [], 51000
    for n, (host, count, data) in enumerate(TRAFFIC):
        for c in range(count):
            port += 1
            six = host in ("www.google.com", "github.com") and c % 2
            user = f"192.168.1.{10 + (n + c) % 4}"
            con = Connection("fd00::25" if six else user, f"2001:db8::{n + 1:x}" if six else f"203.0.113.{n + 1}", port)
            s = [g.udp(user, g.RESOLVER, port, 53, g.dns_query(host))] + con.handshake()
            hello = g.client_hello(host)
            if host == "www.netflix.com":                      # split over two packets
                s += [con.send(0, g.ACK, hello[:60]), con.send(0, g.PSH_ACK, hello[60:])]
            else:
                s.append(con.send(0, g.PSH_ACK, hello))
            for i in range(data):
                s.append(con.send(1, g.PSH_ACK, g.rng.randbytes(g.rng.randrange(200, 1200))) if i % 3 else con.send(0, g.ACK))
            sessions.append(s)
    for host in ("example.com", "httpbin.org"):
        port += 1
        con = Connection("192.168.1.10", "198.51.100.9", port, 80)
        sessions.append(con.handshake() + [con.send(0, g.PSH_ACK, g.http_get(host))])
    # Suspicious: one machine tries many ports on another.
    sessions.append([Connection(g.BLOCKED, "192.168.1.10", 60000 + i, p).send(0, g.SYN)
                     for i, p in enumerate((21, 22, 23, 25, 110, 135, 139, 143, 445, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443))])
    # Suspicious: many long, unique DNS names under one domain.
    sessions.append([g.udp("192.168.1.13", g.RESOLVER, 62000 + i, 53, g.dns_query(g.rng.randbytes(20).hex() + ".data.example.net"))
                     for i in range(14)])
    sessions.append([g.udp("192.168.1.11", "203.0.113.4", 61000, 443, g.rng.randbytes(300)) for _ in range(10)])
    sessions.append([g.frame("192.168.1.12", "8.8.8.8", 1, b"\x08" + bytes(39)) for _ in range(4)])   # ping

    packets = []          # interleave the sessions, keeping each one's own order
    while sessions:
        s = g.rng.choice(sessions)
        packets.append(s.pop(0))
        if not s:
            sessions.remove(s)
    return packets


def write(path):
    packets, times, now = build(), [], 1700000000
    while len(times) < len(packets):          # quiet moments and bursts
        times += [now] * g.rng.choice((1, 1, 2, 3, 5, 9, 14))
        now += g.rng.choice((1, 1, 2, 4))
    g.write_pcap(path, packets, times=times)
    return len(packets)


if __name__ == "__main__":
    target = Path(__file__).resolve().parent.parent / "data" / "sample_traffic.pcap"
    target.parent.mkdir(exist_ok=True)
    print(f"Wrote {write(target)} packets to {target}")
