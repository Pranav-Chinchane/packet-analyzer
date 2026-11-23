#pragma once
#include <fstream>
#include <string>
#include <vector>
#include "pcap_format.h"

// Reads both capture formats: classic .pcap and the newer .pcapng, which is
// what Wireshark saves by default.
class PcapReader {
public:
    enum class Status { Packet, End, Error };

    bool open(const std::string& path);      // false: see error()
    Status next(Packet& packet);             // Error: see error()

    // Classic header in this machine's byte order, ready for PcapWriter.
    const PcapGlobalHeader& header() const { return header_; }
    const std::string& error() const { return error_; }

private:
    struct Interface {                       // pcapng: one per network card
        uint32_t linkType = 0;
        uint32_t snapLen = 0;
        uint64_t unitsPerSecond = 1000000;   // timestamp resolution
    };

    Status nextClassic(Packet& packet);
    Status nextBlock(Packet& packet);        // pcapng
    bool startSection();
    void addInterface();
    Status fail(const std::string& message);
    bool readExact(void* target, size_t size);
    uint16_t u16(size_t offset) const;       // from block_, byte order fixed
    uint32_t u32(size_t offset) const;

    std::vector<char> buffer_;
    std::ifstream file_;
    PcapGlobalHeader header_{};
    bool swap_ = false;
    bool ng_ = false;
    std::vector<Interface> interfaces_;
    std::vector<uint8_t> block_;             // body of the current pcapng block
    std::string error_;
};
