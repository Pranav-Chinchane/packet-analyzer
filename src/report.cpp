#include "report.h"
#include <algorithm>
#include <fstream>
#include <iomanip>

namespace {
constexpr uint64_t MAX_SLOTS = 60;
constexpr size_t MAX_CONNECTIONS = 500;    // busiest ones sent to the web page
}

void printReport(std::ostream& out, const Stats& s, const Insights& insights) {
    auto row = [&](const char* label, uint64_t value) {
        out << "  " << std::left << std::setw(18) << label << ": " << value << "\n";
    };
    out << "\n==================== DPI REPORT ====================\n";
    row("Total packets", s.total);
    row("Total bytes", s.bytes);
    row("TCP packets", s.tcp);
    row("UDP packets", s.udp);
    row("Unsupported", s.unsupported);
    row("Forwarded", s.forwarded);
    row("Dropped", s.dropped);
    row("Flows", s.flows);

    out << "\n-------------------- Summary -----------------------\n";
    for (const auto& line : insights.summary) out << "  " << line << "\n";
    if (!insights.alerts.empty()) {
        out << "\n--------------------- Alerts -----------------------\n";
        for (const auto& a : insights.alerts) out << "  " << a.title << ": " << a.detail << "\n";
    }
    if (!insights.devices.empty()) {
        out << "\n--------------------- Devices ----------------------\n";
        for (const auto& d : insights.devices)
            out << "  " << ipToString(d.ip) << ", " << d.packets << " packets, mostly " << appName(d.topApp()) << "\n";
    }
    out << "\n-------------- Application breakdown ---------------\n";
    std::vector<std::pair<App, uint64_t>> apps(s.appPackets.begin(), s.appPackets.end());
    std::stable_sort(apps.begin(), apps.end(), [](auto& a, auto& b) { return a.second > b.second; });
    for (const auto& [app, n] : apps) {
        const double pct = s.total ? 100.0 * double(n) / double(s.total) : 0;
        out << "  " << std::left << std::setw(15) << appName(app) << std::right << std::setw(9) << n
            << std::setw(7) << std::fixed << std::setprecision(1) << pct << "%  "
            << std::string(static_cast<size_t>(pct / 2.5), '#') << "\n";
    }
    if (!s.names.empty()) {
        out << "\n------------------ Detected names ------------------\n";
        for (const auto& [name, app] : s.names)
            out << "  " << name << " -> " << (app == App::Unknown ? "(no known app)" : appName(app)) << "\n";
    }
    if (!s.blockedFlows.empty()) {
        out << "\n------------------- Blocked flows ------------------\n";
        for (const auto& [why, n] : s.blockedFlows) out << "  " << why << " x" << n << "\n";
    }
    out << "====================================================\n";
}

bool writeJsonReport(const std::string& path, const Stats& s, const Insights& insights,
                     const std::vector<uint64_t>& workerPackets) {
    // Every string here is an app name, IP, validated host name or fixed text,
    // so none of them can contain characters that need JSON escaping.
    std::ofstream out(path, std::ios::trunc);
    const char* sep = "";
    auto next = [&] { out << sep; sep = ","; };
    out << "{\"total\":" << s.total << ",\"bytes\":" << s.bytes << ",\"tcp\":" << s.tcp << ",\"udp\":" << s.udp
        << ",\"unsupported\":" << s.unsupported << ",\"forwarded\":" << s.forwarded
        << ",\"dropped\":" << s.dropped << ",\"flows\":" << s.flows << ",\"apps\":{";
    for (const auto& [app, n] : s.appPackets) { next(); out << '"' << appName(app) << "\":" << n; }
    out << "},\"appsDropped\":{";
    sep = "";
    for (const auto& [app, n] : s.appDropped) { next(); out << '"' << appName(app) << "\":" << n; }
    out << "},\"names\":{";
    sep = "";
    for (const auto& [name, app] : s.names) { next(); out << '"' << name << "\":\"" << (app == App::Unknown ? "" : appName(app)) << '"'; }
    out << "},\"blocked\":{";
    sep = "";
    for (const auto& [why, n] : s.blockedFlows) { next(); out << '"' << why << "\":" << n; }
    out << "},\"workers\":[";
    sep = "";
    for (uint64_t n : workerPackets) { next(); out << n; }
    out << "],\"summary\":[";
    sep = "";
    for (const auto& line : insights.summary) { next(); out << '"' << line << '"'; }
    out << "],\"alerts\":[";
    sep = "";
    for (const auto& a : insights.alerts) {
        next();
        out << "{\"warning\":" << (a.warning ? "true" : "false") << ",\"title\":\"" << a.title << "\",\"detail\":\"" << a.detail << "\"}";
    }
    out << "],\"devices\":[";
    sep = "";
    for (const auto& d : insights.devices) {
        next();
        out << "{\"ip\":\"" << ipToString(d.ip) << "\",\"packets\":" << d.packets << ",\"bytes\":" << d.bytes << ",\"dropped\":" << d.dropped
            << ",\"connections\":" << d.connections << ",\"app\":\"" << appName(d.topApp()) << "\"}";
    }
    // At most 60 equal time slots, each [forwarded, dropped].
    uint64_t start = 0, width = 1;
    std::vector<Stats::Second> slots;
    if (!s.timeline.empty()) {
        start = s.timeline.begin()->first;
        const uint64_t span = s.timeline.rbegin()->first - start + 1;
        width = (span + MAX_SLOTS - 1) / MAX_SLOTS;
        slots.resize(static_cast<size_t>((span + width - 1) / width));
        for (const auto& [second, n] : s.timeline) {
            auto& slot = slots[static_cast<size_t>((second - start) / width)];
            slot.forwarded += n.forwarded;
            slot.dropped += n.dropped;
        }
    }
    out << "],\"timeline\":{\"start\":" << start << ",\"width\":" << width << ",\"slots\":[";
    sep = "";
    for (const auto& slot : slots) { next(); out << '[' << slot.forwarded << ',' << slot.dropped << ']'; }
    out << "]},\"connections\":[";
    sep = "";
    for (size_t i = 0; i < s.connections.size() && i < MAX_CONNECTIONS; i++) {
        const FlowInfo& c = s.connections[i];
        next();
        out << "{\"client\":\"" << ipToString(c.clientIp) << "\",\"clientPort\":" << c.clientPort << ",\"server\":\"" << ipToString(c.serverIp)
            << "\",\"serverPort\":" << c.serverPort << ",\"tcp\":" << (c.protocol == PROTO_TCP ? "true" : "false") << ",\"app\":\"" << appName(c.app)
            << "\",\"name\":\"" << c.name << "\",\"reason\":\"" << c.reason << "\",\"packets\":" << c.packets << ",\"bytes\":" << c.bytes
            << ",\"dropped\":" << c.dropped << '}';
    }
    out << "]}\n";
    out.close();
    return !out.fail();
}
