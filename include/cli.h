#pragma once
#include <string>
#include "rules.h"

struct Options {
    std::string input, output;
    std::string json;          // optional path for a JSON report
    Rules rules;
    int lbs = 2;
    int fps = 2;               // workers per load balancer
};

// Returns true to continue. Otherwise the program should exit with exitCode.
bool parseOptions(int argc, char** argv, bool threaded, Options& options, int& exitCode);
