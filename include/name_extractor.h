#pragma once
// Finds a host name inside application data. All results are lower-case and
// contain only host-name characters, so they are safe to print.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

std::optional<std::string> extractTlsSni(const uint8_t* payload, size_t length);
std::optional<std::string> extractHttpHost(const uint8_t* payload, size_t length);
std::optional<std::string> extractDnsQuery(const uint8_t* payload, size_t length);
