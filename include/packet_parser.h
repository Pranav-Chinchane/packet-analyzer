#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include "ip_address.h"

constexpr uint8_t PROTO_TCP = 6;
constexpr uint8_t PROTO_UDP = 17;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_ACK = 0x10;

struct ParsedPacket {
    IpAddress srcIp, dstIp;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t  protocol = 0;
    uint8_t  tcpFlags = 0;
    uint32_t tcpSeq = 0;
    size_t payloadOffset = 0;  // index into the packet bytes
    size_t payloadLength = 0;
};

// Decodes Ethernet (with optional VLAN tags) -> IPv4 or IPv6 -> TCP or UDP.
// Returns false for anything else (ARP, ICMP, later IP fragments, malformed).
bool parsePacket(const std::vector<uint8_t>& data, ParsedPacket& out);
