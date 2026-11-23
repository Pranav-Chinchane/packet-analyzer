#include "pcap_writer.h"

bool PcapWriter::open(const std::string& path, const PcapGlobalHeader& header) {
    file_.open(path, std::ios::binary | std::ios::trunc);
    if (!file_) return false;
    file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return static_cast<bool>(file_);
}

void PcapWriter::write(const Packet& p) {
    const PcapRecordHeader rec{p.tsSec, p.tsFrac, static_cast<uint32_t>(p.data.size()), p.originalLen};
    file_.write(reinterpret_cast<const char*>(&rec), sizeof(rec));
    file_.write(reinterpret_cast<const char*>(p.data.data()), static_cast<std::streamsize>(p.data.size()));
}

bool PcapWriter::close() {
    file_.close();
    return !file_.fail();
}
