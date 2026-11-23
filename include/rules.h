#pragma once
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>
#include "types.h"

// Filled in before processing starts and only read afterwards, so worker
// threads can share it without a lock.
class Rules {
public:
    // Each returns false if the text is not valid.
    bool blockIp(const std::string& ip);
    bool blockApp(const std::string& app);
    bool blockDomain(const std::string& domain);

    // Reason for blocking, or nullopt to allow.
    std::optional<std::string> check(const FlowKey& key, App app, const std::string& name) const;

private:
    std::set<IpAddress> ips_;
    std::unordered_set<App> apps_;
    std::vector<std::string> domains_;
};
