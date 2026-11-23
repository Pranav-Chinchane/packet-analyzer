#include "packet_parser.h"
#include <algorithm>
#include "byte_order.h"

namespace {

constexpr size_t MAC_ADDRESSES = 12;
constexpr size_t MIN_IPV4 = 20, IPV6_LEN = 40, MIN_TCP = 20, UDP_LEN = 8;
constexpr uint16_t TYPE_IPV4 = 0x0800, TYPE_IPV6 = 0x86DD;

bool isVlan(uint16_t type) { return type == 0x8100 || type == 0x88a8 || type == 0x9100; }

// Both IP parsers set the header length and the end of the IP packet, as
// offsets from ip. Anything after the end is Ethernet padding.
bool parseIpv4(const uint8_t* ip, size_t available, ParsedPacket& out, size_t& headerLen, size_t& end) {
    if (available < MIN_IPV4 || (ip[0] >> 4) != 4) return false;
    headerLen = size_t(ip[0] & 0x0F) * 4;
    if (headerLen < MIN_IPV4 || headerLen > available) return false;
    if (readBE16(ip + 6) & 0x1FFF) return false;     // later fragment: no ports inside
    const size_t total = readBE16(ip + 2);           // 0 with network-card offloading
    end = total == 0 ? available : std::min(total, available);
    out.protocol = ip[9];
    out.srcIp = IpAddress::fromV4(readBE32(ip + 12));
    out.dstIp = IpAddress::fromV4(readBE32(ip + 16));
    return end >= headerLen;
}

bool parseIpv6(const uint8_t* ip, size_t available, ParsedPacket& out, size_t& headerLen, size_t& end) {
    if (available < IPV6_LEN || (ip[0] >> 4) != 6) return false;
    const size_t payload = readBE16(ip + 4);
    end = payload == 0 ? available : std::min(IPV6_LEN + payload, available);
    out.srcIp = IpAddress::fromV6(ip + 8);
    out.dstIp = IpAddress::fromV6(ip + 24);
    uint8_t next = ip[6];
    headerLen = IPV6_LEN;
    for (int i = 0; i < 8; i++) {                    // skip extension headers
        const bool options = next == 0 || next == 43 || next == 60, fragment = next == 44, auth = next == 51;
        if (!options && !fragment && !auth) {
            out.protocol = next;
            return true;
        }
        if (end < headerLen + 8) return false;
        const uint8_t* h = ip + headerLen;
        if (fragment && (readBE16(h + 2) & 0xFFF8)) return false;
        headerLen += fragment ? 8 : auth ? (size_t(h[1]) + 2) * 4 : (size_t(h[1]) + 1) * 8;
        if (headerLen > end) return false;
        next = h[0];
    }
    return false;
}

}  // namespace

bool parsePacket(const std::vector<uint8_t>& data, ParsedPacket& out) {
    out = ParsedPacket{};

    // --- Ethernet: 12 bytes of addresses, optional VLAN tags, then the type ---
    size_t offset = MAC_ADDRESSES;
    if (data.size() < offset + 2) return false;
    uint16_t type = readBE16(&data[offset]);
    for (int i = 0; i < 2 && isVlan(type); i++) {
        offset += 4;
        if (data.size() < offset + 2) return false;
        type = readBE16(&data[offset]);
    }
    offset += 2;

    // --- IP ---
    const uint8_t* ip = data.data() + offset;
    const size_t available = data.size() - offset;
    size_t ipLen = 0, end = 0;
    if (type == TYPE_IPV4) {
        if (!parseIpv4(ip, available, out, ipLen, end)) return false;
    } else if (type == TYPE_IPV6) {
        if (!parseIpv6(ip, available, out, ipLen, end)) return false;
    } else {
        return false;
    }

    // --- TCP / UDP ---
    const uint8_t* t = ip + ipLen;
    const size_t left = end - ipLen;
    size_t headerLen = 0;
    if (out.protocol == PROTO_TCP) {
        if (left < MIN_TCP) return false;
        headerLen = size_t(t[12] >> 4) * 4;
        if (headerLen < MIN_TCP || headerLen > left) return false;
        out.tcpSeq = readBE32(t + 4);
        out.tcpFlags = t[13];
    } else if (out.protocol == PROTO_UDP) {
        if (left < UDP_LEN) return false;
        headerLen = UDP_LEN;
    } else {
        return false;
    }
    out.srcPort = readBE16(t);
    out.dstPort = readBE16(t + 2);
    out.payloadOffset = offset + ipLen + headerLen;
    out.payloadLength = left - headerLen;
    return true;
}
