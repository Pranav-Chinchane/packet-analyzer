#include "fast_path.h"
#include <chrono>

void FastPath::run() {
    while (auto batch = input_.pop()) {
        PacketBatch forwarded;
        forwarded.reserve(batch->size());
        for (PacketJob& job : *batch) {
            if (testDelayMs_ > 0) std::this_thread::sleep_for(std::chrono::milliseconds(testDelayMs_));
            if (processor_.process(job.parsed, job.packet)) forwarded.push_back(std::move(job.packet));
        }
        if (!forwarded.empty()) output_.push(std::move(forwarded));
    }
}

void FastPath::finish() {
    input_.close();
    thread_.join();
}
