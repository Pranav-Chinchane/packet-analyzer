#include "pcap_reader.h"
#include <algorithm>
#include <cstring>
#include "byte_order.h"

namespace {
constexpr uint32_t MAGIC_MICRO = 0xa1b2c3d4, MAGIC_NANO = 0xa1b23c4d;
constexpr uint32_t BLOCK_SECTION = 0x0a0d0d0a, BLOCK_INTERFACE = 1, BLOCK_SIMPLE = 3, BLOCK_PACKET = 6;
constexpr uint32_t BYTE_ORDER_MAGIC = 0x1a2b3c4d;
constexpr uint32_t LINK_ETHERNET = 1;
constexpr uint32_t MAX_PACKET = 262144;          // guards against a corrupt length field
constexpr uint32_t MAX_BLOCK = 16 * 1024 * 1024;

std::string badLink(uint32_t type) { return "unsupported link type " + std::to_string(type) + " (only Ethernet)"; }
}

bool PcapReader::readExact(void* target, size_t size) {
    file_.read(static_cast<char*>(target), static_cast<std::streamsize>(size));
    return file_.gcount() == static_cast<std::streamsize>(size);
}

PcapReader::Status PcapReader::fail(const std::string& message) {
    error_ = message;
    return Status::Error;
}

bool PcapReader::open(const std::string& path) {
    buffer_.resize(1 << 20);
    file_.rdbuf()->pubsetbuf(buffer_.data(), static_cast<std::streamsize>(buffer_.size()));
    file_.open(path, std::ios::binary);
    if (!file_) {
        error_ = "cannot open input file: " + path;
        return false;
    }
    if (!readExact(&header_.magic, 4)) {
        error_ = "file is too short to be a capture";
        return false;
    }
    if (header_.magic == BLOCK_SECTION) {        // pcapng
        ng_ = true;
        if (!startSection()) return false;
        // The filtered file is always written as classic .pcap.
        header_ = PcapGlobalHeader{MAGIC_MICRO, 2, 4, 0, 0, MAX_PACKET, LINK_ETHERNET};
        return true;
    }
    if (!readExact(reinterpret_cast<char*>(&header_) + 4, sizeof(header_) - 4)) {
        error_ = "file is too short to be a capture";
        return false;
    }
    if (header_.magic != MAGIC_MICRO && header_.magic != MAGIC_NANO) {
        swap_ = true;
        header_.magic = swap32(header_.magic);
        header_.versionMajor = swap16(header_.versionMajor);
        header_.versionMinor = swap16(header_.versionMinor);
        header_.timezone = static_cast<int32_t>(swap32(static_cast<uint32_t>(header_.timezone)));
        header_.sigfigs = swap32(header_.sigfigs);
        header_.snaplen = swap32(header_.snaplen);
        header_.linkType = swap32(header_.linkType);
    }
    if (header_.magic != MAGIC_MICRO && header_.magic != MAGIC_NANO) error_ = "not a .pcap or .pcapng file";
    else if (header_.linkType != LINK_ETHERNET) error_ = badLink(header_.linkType);
    return error_.empty();
}

PcapReader::Status PcapReader::next(Packet& packet) {
    return ng_ ? nextBlock(packet) : nextClassic(packet);
}

PcapReader::Status PcapReader::nextClassic(Packet& packet) {
    PcapRecordHeader rec;
    if (!readExact(&rec, sizeof(rec)))
        return file_.gcount() == 0 ? Status::End : fail("input file is truncated (incomplete packet header)");
    if (swap_) {
        rec.tsSec = swap32(rec.tsSec);
        rec.tsFrac = swap32(rec.tsFrac);
        rec.capturedLen = swap32(rec.capturedLen);
        rec.originalLen = swap32(rec.originalLen);
    }
    if (rec.capturedLen > MAX_PACKET)
        return fail("invalid packet length " + std::to_string(rec.capturedLen) + " (corrupt file?)");
    packet.tsSec = rec.tsSec;
    packet.tsFrac = rec.tsFrac;
    packet.originalLen = rec.originalLen;
    packet.data.resize(rec.capturedLen);
    if (!readExact(packet.data.data(), rec.capturedLen)) return fail("input file is truncated (incomplete packet data)");
    return Status::Packet;
}

// ---- pcapng: a list of blocks, each [type][length][body][length] ----

uint16_t PcapReader::u16(size_t offset) const {
    uint16_t v;
    std::memcpy(&v, &block_[offset], 2);
    return swap_ ? swap16(v) : v;
}

uint32_t PcapReader::u32(size_t offset) const {
    uint32_t v;
    std::memcpy(&v, &block_[offset], 4);
    return swap_ ? swap32(v) : v;
}

// Called after the section type was read. A section sets the byte order.
bool PcapReader::startSection() {
    uint32_t head[2];                            // total length, byte-order magic
    if (!readExact(head, sizeof(head))) {
        error_ = "input file is truncated (incomplete section)";
        return false;
    }
    if (head[1] != BYTE_ORDER_MAGIC && head[1] != swap32(BYTE_ORDER_MAGIC)) {
        error_ = "not a valid .pcapng file";
        return false;
    }
    swap_ = head[1] != BYTE_ORDER_MAGIC;
    const uint32_t length = swap_ ? swap32(head[0]) : head[0];
    if (length < 28 || length % 4 || length > MAX_BLOCK) {
        error_ = "not a valid .pcapng file";
        return false;
    }
    block_.resize(length - 12);
    if (!readExact(block_.data(), block_.size())) {
        error_ = "input file is truncated (incomplete section)";
        return false;
    }
    interfaces_.clear();
    return true;
}

void PcapReader::addInterface() {
    Interface in;
    in.linkType = u16(0);
    in.snapLen = u32(4);
    // Options: [code][length][value padded to 4 bytes]. Code 9 is the timestamp resolution.
    for (size_t pos = 8; pos + 4 <= block_.size();) {
        const uint16_t code = u16(pos), length = u16(pos + 2);
        pos += 4;
        if (code == 0 || length > block_.size() - pos) break;
        if (code == 9 && length >= 1) {
            const uint8_t r = block_[pos], power = r & 0x7f;
            if (r & 0x80) {
                if (power < 63) in.unitsPerSecond = uint64_t(1) << power;
            } else if (power <= 18) {
                in.unitsPerSecond = 1;
                for (int i = 0; i < power; i++) in.unitsPerSecond *= 10;
            }
        }
        pos += (size_t(length) + 3) / 4 * 4;
    }
    interfaces_.push_back(in);
}

PcapReader::Status PcapReader::nextBlock(Packet& packet) {
    for (;;) {
        uint32_t type = 0, length = 0;
        if (!readExact(&type, 4)) return file_.gcount() == 0 ? Status::End : fail("input file is truncated");
        if (type == BLOCK_SECTION) {             // same value in both byte orders
            if (!startSection()) return Status::Error;
            continue;
        }
        if (!readExact(&length, 4)) return fail("input file is truncated");
        if (swap_) { type = swap32(type); length = swap32(length); }
        if (length < 12 || length % 4 || length > MAX_BLOCK) return fail("invalid block length (corrupt file?)");
        block_.resize(length - 8);
        if (!readExact(block_.data(), block_.size())) return fail("input file is truncated (incomplete block)");
        block_.resize(length - 12);              // drop the repeated length

        size_t start = 0, captured = 0;
        uint32_t original = 0, id = 0;
        uint64_t ticks = 0;
        if (type == BLOCK_INTERFACE) {
            if (block_.size() < 8) return fail("invalid interface block (corrupt file?)");
            addInterface();
            continue;
        } else if (type == BLOCK_PACKET) {
            if (block_.size() < 20) return fail("invalid packet block (corrupt file?)");
            id = u32(0);
            ticks = uint64_t(u32(4)) << 32 | u32(8);
            captured = u32(12);
            original = u32(16);
            start = 20;
        } else if (type == BLOCK_SIMPLE) {       // has no timestamp
            if (block_.size() < 4) return fail("invalid packet block (corrupt file?)");
            original = u32(0);
            start = 4;
            captured = std::min<size_t>(original, block_.size() - start);
            if (!interfaces_.empty() && interfaces_[0].snapLen) captured = std::min<size_t>(captured, interfaces_[0].snapLen);
        } else {
            continue;                            // names, statistics, comments...
        }
        if (id >= interfaces_.size()) return fail("packet without an interface (corrupt file?)");
        if (interfaces_[id].linkType != LINK_ETHERNET) return fail(badLink(interfaces_[id].linkType));
        if (captured > block_.size() - start || captured > MAX_PACKET)
            return fail("invalid packet length " + std::to_string(captured) + " (corrupt file?)");
        const uint64_t units = interfaces_[id].unitsPerSecond;
        packet.tsSec = static_cast<uint32_t>(ticks / units);
        packet.tsFrac = static_cast<uint32_t>(static_cast<long double>(ticks % units) * 1000000 / units);
        packet.originalLen = original;
        const auto first = block_.begin() + static_cast<std::ptrdiff_t>(start);
        packet.data.assign(first, first + static_cast<std::ptrdiff_t>(captured));
        return Status::Packet;
    }
}
