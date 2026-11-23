#include "ip_address.h"
#include <vector>

IpAddress IpAddress::fromV4(uint32_t v4) {
    IpAddress ip;
    ip.bytes[10] = ip.bytes[11] = 0xff;
    for (size_t i = 0; i < 4; i++) ip.bytes[12 + i] = static_cast<uint8_t>(v4 >> (24 - 8 * i));
    return ip;
}

IpAddress IpAddress::fromV6(const uint8_t* network) {
    IpAddress ip;
    std::memcpy(ip.bytes.data(), network, 16);
    return ip;
}

bool IpAddress::isV4() const {
    for (size_t i = 0; i < 10; i++)
        if (bytes[i] != 0) return false;
    return bytes[10] == 0xff && bytes[11] == 0xff;
}

bool IpAddress::isPrivate() const {
    if (isV4()) {
        const uint8_t a = bytes[12], b = bytes[13];
        return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 169 && b == 254);
    }
    return (bytes[0] & 0xfe) == 0xfc || (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80);
}

static std::optional<IpAddress> parseV4(const std::string& text) {
    uint32_t ip = 0;
    unsigned octet = 0, digits = 0, dots = 0;
    for (char c : text) {
        if (c >= '0' && c <= '9') {
            octet = octet * 10 + unsigned(c - '0');
            if (++digits > 3 || octet > 255) return std::nullopt;
        } else if (c == '.' && digits > 0 && dots < 3) {
            ip = (ip << 8) | octet;
            octet = digits = 0;
            dots++;
        } else {
            return std::nullopt;
        }
    }
    if (dots != 3 || digits == 0) return std::nullopt;
    return IpAddress::fromV4((ip << 8) | octet);
}

// Parses "2001:db8:1" into 16-bit groups. False if any group is invalid.
static bool parseGroups(const std::string& text, std::vector<unsigned>& groups) {
    if (text.empty()) return true;
    unsigned value = 0, digits = 0;
    for (size_t i = 0; i <= text.size(); i++) {
        if (i == text.size() || text[i] == ':') {
            if (digits == 0) return false;
            groups.push_back(value);
            value = digits = 0;
            continue;
        }
        const char c = text[i];
        unsigned d = 0;
        if (c >= '0' && c <= '9') d = unsigned(c - '0');
        else if (c >= 'a' && c <= 'f') d = unsigned(c - 'a') + 10;
        else if (c >= 'A' && c <= 'F') d = unsigned(c - 'A') + 10;
        else return false;
        if (++digits > 4) return false;
        value = value * 16 + d;
    }
    return true;
}

std::optional<IpAddress> parseIp(const std::string& text) {
    if (text.find(':') == std::string::npos) return parseV4(text);
    std::vector<unsigned> left, right;
    const size_t gap = text.find("::");              // "::" stands for a run of zeros
    if (gap == std::string::npos) {
        if (!parseGroups(text, left) || left.size() != 8) return std::nullopt;
    } else {
        if (!parseGroups(text.substr(0, gap), left) || !parseGroups(text.substr(gap + 2), right)) return std::nullopt;
        if (left.size() + right.size() > 7) return std::nullopt;
        left.resize(8 - right.size(), 0);
        left.insert(left.end(), right.begin(), right.end());
    }
    IpAddress ip;
    for (size_t i = 0; i < 8; i++) {
        ip.bytes[2 * i] = static_cast<uint8_t>(left[i] >> 8);
        ip.bytes[2 * i + 1] = static_cast<uint8_t>(left[i]);
    }
    return ip;
}

std::string ipToString(const IpAddress& ip) {
    const auto& b = ip.bytes;
    if (ip.isV4())
        return std::to_string(b[12]) + "." + std::to_string(b[13]) + "." + std::to_string(b[14]) + "." + std::to_string(b[15]);
    unsigned g[8];
    for (size_t i = 0; i < 8; i++) g[i] = unsigned(b[2 * i]) << 8 | b[2 * i + 1];
    size_t best = 8, bestLen = 1;                    // longest run of two or more zero groups
    for (size_t i = 0; i < 8; i++) {
        size_t n = 0;
        while (i + n < 8 && g[i + n] == 0) n++;
        if (n > bestLen) { best = i; bestLen = n; }
    }
    static const char hex[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < 8; i++) {
        if (i == best) {
            out += "::";
            i += bestLen - 1;
            continue;
        }
        if (!out.empty() && out.back() != ':') out += ':';
        bool started = false;
        for (int shift = 12; shift >= 0; shift -= 4) {
            const unsigned d = (g[i] >> shift) & 15;
            if (d || started || shift == 0) { out += hex[d]; started = true; }
        }
    }
    return out;
}
