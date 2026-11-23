#pragma once
#include <thread>
#include <vector>
#include "flow_processor.h"
#include "pcap_format.h"
#include "thread_safe_queue.h"

struct PacketJob {
    Packet packet;
    ParsedPacket parsed;
    size_t hash = 0;           // of the flow key
};

// Threads exchange packets in batches. Locking a queue once per packet costs
// more than inspecting the packet.
constexpr size_t BATCH_SIZE = 256;
constexpr size_t QUEUE_BATCHES = 64;
using JobBatch = std::vector<PacketJob>;
using PacketBatch = std::vector<Packet>;

// Worker thread: inspects packets and applies the rules. Every packet of a
// flow reaches the same worker, so its flow table needs no lock.
class FastPath {
public:
    FastPath(const Rules& rules, ThreadSafeQueue<PacketBatch>& output, int testDelayMs)
        : processor_(rules), output_(output), testDelayMs_(testDelayMs) {}

    void start() { thread_ = std::thread(&FastPath::run, this); }
    void push(JobBatch batch) { input_.push(std::move(batch)); }
    void finish();                                        // process everything queued, then stop
    Stats stats() { return processor_.finish(); }   // once, after finish()

private:
    void run();

    FlowProcessor processor_;
    ThreadSafeQueue<PacketBatch>& output_;
    int testDelayMs_;
    ThreadSafeQueue<JobBatch> input_{QUEUE_BATCHES};
    std::thread thread_;
};
