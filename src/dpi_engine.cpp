#include "dpi_engine.h"
#include <memory>
#include <thread>
#include <utility>
#include "load_balancer.h"
#include "pcap_reader.h"
#include "pcap_writer.h"

EngineResult runEngine(const EngineConfig& config, const Rules& rules) {
    EngineResult result;
    PcapReader reader;
    if (!reader.open(config.input)) {
        result.error = reader.error();
        return result;
    }
    PcapWriter writer;
    if (!writer.open(config.output, reader.header())) {
        result.error = "cannot write output file: " + config.output;
        return result;
    }
    result.started = true;

    // --- build the pipeline ---
    const size_t lbCount = static_cast<size_t>(config.lbs);
    const size_t fpsPerLb = static_cast<size_t>(config.fps);
    ThreadSafeQueue<PacketBatch> output(QUEUE_BATCHES);
    std::vector<std::unique_ptr<FastPath>> workers;
    std::vector<std::unique_ptr<LoadBalancer>> balancers;
    for (size_t i = 0; i < lbCount; i++) {
        std::vector<FastPath*> group;
        for (size_t j = 0; j < fpsPerLb; j++) {
            workers.push_back(std::make_unique<FastPath>(rules, output, config.testDelayMs));
            group.push_back(workers.back().get());
        }
        balancers.push_back(std::make_unique<LoadBalancer>(std::move(group), lbCount));
    }

    // --- start, consumers first ---
    std::thread writerThread([&] {
        while (auto batch = output.pop())
            for (const Packet& packet : *batch) writer.write(packet);
    });
    for (auto& w : workers) w->start();
    for (auto& b : balancers) b->start();

    // --- read and dispatch ---
    Stats unsupported;
    std::vector<JobBatch> batches(lbCount);
    PacketBatch direct;                          // packets that need no inspection
    PacketJob job;
    PcapReader::Status status;
    while ((status = reader.next(job.packet)) == PcapReader::Status::Packet) {
        if (parsePacket(job.packet.data, job.parsed)) {
            job.hash = FlowKeyHash{}(makeFlowKey(job.parsed));
            const size_t lb = job.hash % lbCount;
            batches[lb].push_back(std::move(job));
            if (batches[lb].size() == BATCH_SIZE) balancers[lb]->push(std::exchange(batches[lb], {}));
        } else {
            unsupported.countUnsupported(job.packet);
            direct.push_back(std::move(job.packet));
            if (direct.size() == BATCH_SIZE) output.push(std::exchange(direct, {}));
        }
        job = PacketJob{};
    }
    for (size_t i = 0; i < lbCount; i++)         // send the unfinished batches
        if (!batches[i].empty()) balancers[i]->push(std::move(batches[i]));
    if (!direct.empty()) output.push(std::move(direct));

    // --- stop in pipeline order; each stage drains before the next closes ---
    for (auto& b : balancers) b->finish();
    for (auto& w : workers) w->finish();
    output.close();
    writerThread.join();

    result.stats = unsupported;
    for (auto& w : workers) {
        Stats s = w->stats();
        result.workerPackets.push_back(s.total);
        result.stats.add(std::move(s));
    }
    if (!writer.close()) result.error = "writing the output file failed";
    else if (status == PcapReader::Status::Error) result.error = reader.error();
    return result;
}
