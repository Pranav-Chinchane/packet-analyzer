#pragma once
#include <string>
#include <vector>
#include "flow_processor.h"

struct EngineConfig {
    std::string input, output;
    int lbs = 2;
    int fps = 2;
    int testDelayMs = 0;       // slows workers; used only by tests
};

struct EngineResult {
    std::string error;         // empty on success
    bool started = false;      // true if stats are meaningful
    Stats stats;
    std::vector<uint64_t> workerPackets;
};

// Reader (calling thread) -> load balancers -> workers -> writer thread.
EngineResult runEngine(const EngineConfig& config, const Rules& rules);
