#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

// One type for IPv4 and IPv6. An IPv4 address is stored in the standard
// "IPv4-mapped" IPv6 form ::ffff:a.b.c.d, so the rest of the program does not
// need two versions of everything.
struct IpAddress {
    std::array<uint8_t, 16> bytes{};

    static IpAddress fromV4(uint32_t v4);              // 1.2.3.4 is 0x01020304
    static IpAddress fromV6(const uint8_t* network);   // 16 bytes from a packet
    bool isV4() const;
    bool isPrivate() const;                            // home/office network address

    bool operator==(const IpAddress& o) const { return bytes == o.bytes; }
    bool operator<(const IpAddress& o) const { return bytes < o.bytes; }
};

std::optional<IpAddress> parseIp(const std::string& text);
std::string ipToString(const IpAddress& ip);
