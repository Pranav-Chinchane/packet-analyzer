"""Creates data/test_dpi.pcap: 77 synthetic packets with known contents."""
import random
import struct
from pathlib import Path

USER, RESOLVER = "192.168.1.100", "8.8.8.8"
BLOCKED = "192.168.1.50"
USER_MAC, ROUTER_MAC = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")
SYN, SYN_ACK, ACK, PSH_ACK = 0x02, 0x12, 0x10, 0x18

SITES = ["www.google.com", "www.youtube.com", "www.facebook.com", "www.instagram.com",
         "twitter.com", "www.amazon.com", "www.netflix.com", "github.com", "discord.com",
         "zoom.us", "web.telegram.org", "www.tiktok.com", "open.spotify.com",
         "www.cloudflare.com", "www.microsoft.com", "www.apple.com"]
HTTP_HOSTS = ["example.com", "httpbin.org"]
DNS_NAMES = ["www.google.com", "www.youtube.com", "www.facebook.com", "api.twitter.com"]

rng = random.Random(42)     # fixed seed: the same file every time


def frame(src, dst, proto, body):
    macs = ROUTER_MAC + USER_MAC if src.startswith("192.168.") else USER_MAC + ROUTER_MAC
    addr = bytes(int(x) for x in (src + "." + dst).split("."))
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(body), 1, 0x4000, 64, proto, 0) + addr
    return macs + b"\x08\x00" + ip + body


def tcp(src, dst, sport, dport, flags, payload=b"", seq=1, ack=0):
    head = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return frame(src, dst, 6, head + payload)


def udp(src, dst, sport, dport, payload):
    return frame(src, dst, 17, struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload)


def client_hello(host):
    name = host.encode()
    entry = b"\x00" + struct.pack(">H", len(name)) + name
    sni = struct.pack(">HHH", 0, len(entry) + 2, len(entry)) + entry
    versions = struct.pack(">HHBH", 0x2B, 3, 2, 0x0304)
    exts = versions + sni                      # SNI is deliberately not first
    body = (b"\x03\x03" + rng.randbytes(32) + b"\x00" + struct.pack(">HHH", 4, 0x1301, 0x1302)
            + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def http_get(host):
    return f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n".encode()


def dns_query(name):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    head = struct.pack(">HHHHHH", rng.randrange(65536), 0x0100, 1, 0, 0, 0)
    return head + labels + b"\x00" + struct.pack(">HH", 1, 1)


def sample_packets():
    rng.seed(42)
    packets, port = [], 50000
    for i, host in enumerate(SITES):
        server, port = f"203.0.113.{i + 1}", port + 1
        packets += [tcp(USER, server, port, 443, SYN, seq=100),
                    tcp(server, USER, 443, port, SYN_ACK, seq=900, ack=101),
                    tcp(USER, server, port, 443, ACK, seq=101, ack=901),
                    tcp(USER, server, port, 443, PSH_ACK, client_hello(host), seq=101, ack=901)]
    for i, host in enumerate(HTTP_HOSTS):
        server, port = f"198.51.100.{i + 1}", port + 1
        packets += [tcp(USER, server, port, 80, SYN, seq=100),
                    tcp(USER, server, port, 80, PSH_ACK, http_get(host), seq=101, ack=1)]
    for name in DNS_NAMES:
        port += 1
        packets.append(udp(USER, RESOLVER, port, 53, dns_query(name)))
    for _ in range(5):
        port += 1
        packets.append(tcp(BLOCKED, "203.0.113.200", port, 443, SYN))
    return packets


def write_pcap(path, packets, endian="<", original_len=None, times=None):
    with open(path, "wb") as f:
        f.write(struct.pack(endian + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(packets):
            f.write(struct.pack(endian + "IIII", times[i] if times else 1700000000 + i, 0, len(p), original_len or len(p)) + p)


if __name__ == "__main__":
    target = Path(__file__).resolve().parent.parent / "data" / "test_dpi.pcap"
    target.parent.mkdir(exist_ok=True)
    pkts = sample_packets()
    write_pcap(target, pkts)
    print(f"Wrote {len(pkts)} packets to {target}")
