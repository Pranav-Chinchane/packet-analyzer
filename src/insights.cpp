#include "insights.h"
#include <algorithm>
#include <cstdio>
#include <tuple>

namespace {

// Alert thresholds. They are simple rules of thumb, so alerts say "possible".
constexpr size_t SCAN_PORTS = 15;          // ports tried on one machine
constexpr size_t SCAN_HOSTS = 20;          // machines tried on one port, unanswered
constexpr size_t TUNNEL_NAMES = 10;        // long names under one domain
constexpr size_t TUNNEL_LENGTH = 30;       // characters before the domain

std::string count(uint64_t n, const char* word) {
    return std::to_string(n) + " " + word + (n == 1 ? "" : "s");
}

std::string percent(uint64_t part, uint64_t whole) {
    char text[16];
    std::snprintf(text, sizeof(text), "%.1f%%", whole ? 100.0 * double(part) / double(whole) : 0.0);
    return text;
}

std::string duration(uint64_t s) {
    if (s < 60) return count(s, "second");
    if (s < 3600) return count(s / 60, "minute") + (s % 60 ? " " + count(s % 60, "second") : "");
    return count(s / 3600, "hour") + (s / 60 % 60 ? " " + count(s / 60 % 60, "minute") : "");
}

void findScans(const Stats& s, std::vector<Alert>& alerts) {
    std::map<std::pair<IpAddress, IpAddress>, std::set<uint16_t>> ports;   // client, server -> ports
    std::map<std::pair<IpAddress, uint16_t>, std::set<IpAddress>> hosts;   // client, port -> servers
    for (const auto& c : s.connections) {
        // Only connections whose start was seen: otherwise the replies in a
        // capture that began late could look like a scan.
        if (!c.opened) continue;
        ports[{c.clientIp, c.serverIp}].insert(c.serverPort);
        if (!c.answered) hosts[{c.clientIp, c.serverPort}].insert(c.serverIp);
    }
    for (const auto& [pair, set] : ports)
        if (set.size() >= SCAN_PORTS)
            alerts.push_back({true, "Possible port scan", ipToString(pair.first) + " tried " + count(set.size(), "port") +
                              " on " + ipToString(pair.second) + "."});
    for (const auto& [pair, set] : hosts)
        if (set.size() >= SCAN_HOSTS)
            alerts.push_back({true, "Possible network scan", ipToString(pair.first) + " tried port " + std::to_string(pair.second) +
                              " on " + count(set.size(), "machine") + " without an answer."});
}

// Data can be smuggled out inside many long, unique DNS names.
void findDnsTunnels(const Stats& s, std::vector<Alert>& alerts) {
    for (const auto& [ip, asked] : s.dns) {
        std::map<std::string, size_t> longNames;       // parent domain -> count
        for (const auto& name : asked) {
            const size_t last = name.rfind('.');
            if (last == std::string::npos || last == 0) continue;
            const size_t before = name.rfind('.', last - 1);
            // Reverse lookups (address to name) are long but normal.
            if (name.compare(last, std::string::npos, ".arpa") == 0) continue;
            if (before != std::string::npos && before >= TUNNEL_LENGTH) longNames[name.substr(before + 1)]++;
        }
        for (const auto& [domain, n] : longNames)
            if (n >= TUNNEL_NAMES)
                alerts.push_back({true, "Unusual DNS activity", ipToString(ip) + " looked up " + count(n, "long, unique name") +
                                  " under " + domain + ". This can be a hidden data channel."});
    }
}

void findUnencrypted(const Stats& s, std::vector<Alert>& alerts) {
    std::set<std::string> sites;
    std::map<uint16_t, uint64_t> logins;
    for (const auto& c : s.connections) {
        if (c.plainHttp) sites.insert(c.name);
        if (c.protocol == PROTO_TCP && c.answered && (c.serverPort == 21 || c.serverPort == 23)) logins[c.serverPort]++;
    }
    for (const auto& [port, n] : logins)
        alerts.push_back({true, "Unencrypted login protocol", count(n, "connection") + " used " + (port == 21 ? "FTP" : "Telnet") +
                          ", which sends passwords without encryption."});
    if (sites.empty()) return;
    std::string list;
    size_t shown = 0;
    for (const auto& site : sites) {
        if (shown == 3) break;
        list += (shown++ ? ", " : "") + site;
    }
    if (sites.size() > shown) list += " and " + std::to_string(sites.size() - shown) + " more";
    alerts.push_back({false, "Unencrypted web traffic", "Others on the network can read traffic to " + list + "."});
}

std::vector<Device> findDevices(const Stats& s) {
    std::map<IpAddress, Device> found;
    for (const auto& c : s.connections) {
        for (const IpAddress* ip : {&c.clientIp, &c.serverIp}) {
            if (!ip->isPrivate() || (ip == &c.serverIp && c.serverIp == c.clientIp)) continue;
            Device& d = found[*ip];
            d.ip = *ip;
            d.packets += c.packets;
            d.bytes += c.bytes;
            d.dropped += c.dropped;
            d.connections++;
            d.apps[c.app] += c.packets;
        }
    }
    std::vector<Device> devices;
    for (auto& [ip, d] : found) devices.push_back(std::move(d));
    std::stable_sort(devices.begin(), devices.end(), [](auto& a, auto& b) { return a.packets > b.packets; });
    return devices;
}

}  // namespace

App Device::topApp() const {
    App best = App::Unknown;
    uint64_t most = 0;
    for (const auto& [app, n] : apps)
        if (n > most) { best = app; most = n; }
    return best;
}

Insights buildInsights(Stats& s) {
    // Fixed order, so the result never depends on thread timing.
    std::sort(s.connections.begin(), s.connections.end(), [](const FlowInfo& a, const FlowInfo& b) {
        return std::tie(b.packets, a.clientIp, a.clientPort, a.serverIp, a.serverPort, a.protocol) <
               std::tie(a.packets, b.clientIp, b.clientPort, b.serverIp, b.serverPort, b.protocol);
    });
    Insights r;
    r.devices = findDevices(s);
    findScans(s, r.alerts);
    findDnsTunnels(s, r.alerts);
    findUnencrypted(s, r.alerts);

    if (s.total == 0) {
        r.summary.push_back("The capture is empty.");
        return r;
    }
    const uint64_t seconds = s.timeline.rbegin()->first - s.timeline.begin()->first;
    r.summary.push_back(count(s.total, "packet") + " in " + count(s.flows, "connection") +
                        (seconds ? " over " + duration(seconds) : std::string(" within one second")) + ".");
    App top = App::Unknown;
    uint64_t most = 0;
    for (const auto& [app, n] : s.appPackets)
        if (app != App::Unknown && n > most) { top = app; most = n; }
    if (most) r.summary.push_back(std::string(appName(top)) + " made up the most traffic: " + percent(most, s.total) + " of packets.");
    if (!r.devices.empty())
        r.summary.push_back(count(r.devices.size(), "device") + " on the local network. The busiest was " + ipToString(r.devices[0].ip) + ".");
    r.summary.push_back(s.dropped ? "Your rules blocked " + count(s.dropped, "packet") + " (" + percent(s.dropped, s.total) + ")."
                                  : std::string("Nothing was blocked."));
    return r;
}
