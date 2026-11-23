#pragma once
#include <fstream>
#include <string>
#include "pcap_format.h"

class PcapWriter {
public:
    bool open(const std::string& path, const PcapGlobalHeader& header);
    void write(const Packet& packet);
    bool close();                            // false if any write failed (e.g. disk full)

private:
    std::ofstream file_;
};
