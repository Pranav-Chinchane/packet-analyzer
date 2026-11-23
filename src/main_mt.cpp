// Multi-threaded DPI program.
#include <iostream>
#include "cli.h"
#include "dpi_engine.h"
#include "report.h"

int main(int argc, char** argv) {
    Options options;
    int exitCode = 0;
    if (!parseOptions(argc, argv, true, options, exitCode)) return exitCode;

    EngineConfig config;
    config.input = options.input;
    config.output = options.output;
    config.lbs = options.lbs;
    config.fps = options.fps;
    EngineResult result = runEngine(config, options.rules);

    if (result.started) {
        const Insights insights = buildInsights(result.stats);
        if (!options.json.empty() && !writeJsonReport(options.json, result.stats, insights, result.workerPackets)) {
            std::cerr << "Error: cannot write JSON report: " << options.json << "\n";
            return 1;
        }
        printReport(std::cout, result.stats, insights);
        std::cout << "Threads: " << options.lbs << " load balancers x " << options.fps << " workers\n";
        for (size_t i = 0; i < result.workerPackets.size(); i++)
            std::cout << "  Worker " << i << " packets : " << result.workerPackets[i] << "\n";
    }
    if (!result.error.empty()) {
        std::cerr << "Error: " << result.error << "\n";
        return 1;
    }
    std::cout << "Output written to: " << options.output << "\n";
    return 0;
}
