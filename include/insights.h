#pragma once
// Turns the raw statistics into things a person wants to know.
#include <string>
#include <vector>
#include "flow_processor.h"

struct Alert {
    bool warning = false;      // false: for information
    std::string title, detail;
};

struct Device {                // a private (home/office) address
    IpAddress ip;
    uint64_t packets = 0, bytes = 0, dropped = 0, connections = 0;
    std::map<App, uint64_t> apps;
    App topApp() const;
};

struct Insights {
    std::vector<std::string> summary;
    std::vector<Alert> alerts;
    std::vector<Device> devices;           // busiest first
};

// Sorts stats.connections (busiest first) and analyses them.
Insights buildInsights(Stats& stats);
