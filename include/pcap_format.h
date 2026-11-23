#pragma once
// On-disk layout of the classic .pcap format, plus our in-memory packet.
#include <cstdint>
#include <vector>

struct PcapGlobalHeader {      // 24 bytes, once per file
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    int32_t  timezone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linkType;         // 1 = Ethernet
};
static_assert(sizeof(PcapGlobalHeader) == 24, "unexpected padding");

struct PcapRecordHeader {      // 16 bytes, before every packet
    uint32_t tsSec;
    uint32_t tsFrac;
    uint32_t capturedLen;      // bytes stored in the file
    uint32_t originalLen;      // bytes the packet had on the wire
};
static_assert(sizeof(PcapRecordHeader) == 16, "unexpected padding");

struct Packet {
    uint32_t tsSec = 0;
    uint32_t tsFrac = 0;
    uint32_t originalLen = 0;
    std::vector<uint8_t> data;
};
