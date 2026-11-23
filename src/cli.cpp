#include "cli.h"
#include <charconv>
#include <filesystem>
#include <iostream>

namespace {

void usage(const char* program, bool threaded) {
    std::cout << "Usage: " << program << " <input.pcap> <output.pcap> [options]\n\n"
              << "  --block-ip <ip>          block traffic to or from an IPv4 or IPv6 address\n"
              << "  --block-app <app>        block an app, e.g. YouTube\n"
              << "  --block-domain <domain>  block a domain, its subdomains and its DNS lookups\n"
              << "  --json <file>            also write the report as JSON\n";
    if (threaded)
        std::cout << "  --lbs <1-64>             load balancer threads (default 2)\n"
                  << "  --fps <1-64>             worker threads per load balancer (default 2)\n";
    std::cout << "\nBlock options can be repeated. Apps:";
    for (int i = 1; i < static_cast<int>(App::Count); i++) std::cout << (i > 1 ? ", " : " ") << appName(static_cast<App>(i));
    std::cout << "\n";
}

bool parseThreads(const std::string& text, int& out) {
    const char* end = text.data() + text.size();
    const auto r = std::from_chars(text.data(), end, out);
    return r.ec == std::errc() && r.ptr == end && out >= 1 && out <= 64;
}

}  // namespace

bool parseOptions(int argc, char** argv, bool threaded, Options& o, int& exitCode) {
    exitCode = 1;
    auto fail = [](const std::string& message) {
        std::cerr << "Error: " << message << "\n";
        return false;
    };
    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        if (a == "--help" || a == "-h") {
            usage(argv[0], threaded);
            exitCode = 0;
            return false;
        }
    }
    if (argc < 3) {
        usage(argv[0], threaded);
        return false;
    }
    o.input = argv[1];
    o.output = argv[2];
    for (int i = 3; i < argc; i += 2) {
        const std::string name = argv[i];
        const bool known = name == "--block-ip" || name == "--block-app" || name == "--block-domain" ||
                           name == "--json" ||
                           (threaded && (name == "--lbs" || name == "--fps"));
        if (!known) return fail("unknown option " + name);
        if (i + 1 >= argc) return fail(name + " needs a value");
        const std::string value = argv[i + 1];
        bool ok = false;
        if (name == "--block-ip") ok = o.rules.blockIp(value);
        else if (name == "--block-app") ok = o.rules.blockApp(value);
        else if (name == "--block-domain") ok = o.rules.blockDomain(value);
        else if (name == "--json") { o.json = value; ok = !value.empty(); }
        else ok = parseThreads(value, name == "--lbs" ? o.lbs : o.fps);
        if (!ok) return fail("invalid value for " + name + ": " + value);
    }
    // Opening the output erases it, so it must not be the input.
    std::error_code ec;
    if (std::filesystem::equivalent(o.input, o.output, ec)) return fail("input and output are the same file");
    if (!o.json.empty()) {
        const auto json = std::filesystem::weakly_canonical(o.json, ec);
        for (const auto& other : {o.input, o.output})
            if (json == std::filesystem::weakly_canonical(other, ec) || std::filesystem::equivalent(o.json, other, ec))
                return fail("the JSON report needs its own file");
    }
    return true;
}
