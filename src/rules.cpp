#include "rules.h"

bool Rules::blockIp(const std::string& ip) {
    const auto parsed = parseIp(ip);
    if (parsed) ips_.insert(*parsed);
    return parsed.has_value();
}

bool Rules::blockApp(const std::string& app) {
    const auto parsed = appFromName(app);
    if (parsed) apps_.insert(*parsed);
    return parsed.has_value();
}

bool Rules::blockDomain(const std::string& domain) {
    std::string d = toLower(domain);
    while (!d.empty() && d.back() == '.') d.pop_back();
    while (!d.empty() && d.front() == '.') d.erase(0, 1);
    if (d.empty() || d.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789.-_") != std::string::npos)
        return false;
    domains_.push_back(d);
    return true;
}

std::optional<std::string> Rules::check(const FlowKey& key, App app, const std::string& name) const {
    for (const IpAddress& ip : {key.ipA, key.ipB})
        if (ips_.count(ip)) return "IP " + ipToString(ip);
    if (apps_.count(app)) return std::string("app ") + appName(app);
    for (const auto& d : domains_)
        if (matchesDomain(name, d)) return "domain " + d;
    return std::nullopt;
}
