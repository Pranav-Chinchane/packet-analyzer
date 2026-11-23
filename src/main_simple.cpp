// Single-threaded DPI program.
#include <iostream>
#include "cli.h"
#include "pcap_reader.h"
#include "pcap_writer.h"
#include "report.h"

int main(int argc, char** argv) {
    Options options;
    int exitCode = 0;
    if (!parseOptions(argc, argv, false, options, exitCode)) return exitCode;

    PcapReader reader;
    if (!reader.open(options.input)) {
        std::cerr << "Error: " << reader.error() << "\n";
        return 1;
    }
    PcapWriter writer;
    if (!writer.open(options.output, reader.header())) {
        std::cerr << "Error: cannot write output file: " << options.output << "\n";
        return 1;
    }

    FlowProcessor processor(options.rules);
    Stats unsupported;
    Packet packet;
    ParsedPacket parsed;
    PcapReader::Status status;
    while ((status = reader.next(packet)) == PcapReader::Status::Packet) {
        bool forward = true;
        if (parsePacket(packet.data, parsed)) forward = processor.process(parsed, packet);
        else unsupported.countUnsupported(packet);
        if (forward) writer.write(packet);
    }

    Stats stats = processor.finish();
    stats.add(unsupported);
    const Insights insights = buildInsights(stats);
    const bool written = writer.close();
    printReport(std::cout, stats, insights);
    if (!options.json.empty() && !writeJsonReport(options.json, stats, insights, {})) {
        std::cerr << "Error: cannot write JSON report: " << options.json << "\n";
        return 1;
    }
    if (status == PcapReader::Status::Error) std::cerr << "Error: " << reader.error() << "\n";
    if (!written) std::cerr << "Error: writing the output file failed\n";
    if (status == PcapReader::Status::Error || !written) return 1;
    std::cout << "Output written to: " << options.output << "\n";
    return 0;
}
