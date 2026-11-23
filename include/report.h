#pragma once
#include <ostream>
#include <string>
#include <vector>
#include "insights.h"

void printReport(std::ostream& out, const Stats& stats, const Insights& insights);

// Machine-readable report for the web UI. False if the file cannot be written.
bool writeJsonReport(const std::string& path, const Stats& stats, const Insights& insights,
                     const std::vector<uint64_t>& workerPackets);
