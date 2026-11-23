#include "name_extractor.h"
#include <algorithm>
#include <cstring>
#include <string_view>
#include "byte_order.h"
#include "types.h"

namespace {

std::optional<std::string> cleanName(std::string name) {
    while (!name.empty() && name.back() == '.') name.pop_back();
    if (name.empty() || name.size() > 253) return std::nullopt;
    name = toLower(std::move(name));
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        if (!ok) return std::nullopt;
    }
    return name;
}

// Walks through bytes without ever going past the end.
class Cursor {
public:
    Cursor(const uint8_t* data, size_t length) : p_(data), left_(length) {}
    bool skip(size_t n) {
        if (n > left_) return false;
        p_ += n;
        left_ -= n;
        return true;
    }
    bool u8(size_t& v) {
        if (left_ < 1) return false;
        v = *p_;
        return skip(1);
    }
    bool u16(size_t& v) {
        if (left_ < 2) return false;
        v = readBE16(p_);
        return skip(2);
    }
    const uint8_t* data() const { return p_; }
    size_t left() const { return left_; }

private:
    const uint8_t* p_;
    size_t left_;
};

}  // namespace

std::optional<std::string> extractTlsSni(const uint8_t* payload, size_t length) {
    if (length < 9 || payload[0] != 0x16 || payload[1] != 0x03 || payload[5] != 0x01)
        return std::nullopt;                              // not a TLS Client Hello

    const size_t recordEnd = 5 + size_t(readBE16(payload + 3));
    Cursor c(payload, std::min(length, recordEnd));
    size_t n = 0;
    if (!c.skip(5 + 4 + 2 + 32)) return std::nullopt;     // record, handshake, version, random
    if (!c.u8(n) || !c.skip(n)) return std::nullopt;      // session id
    if (!c.u16(n) || !c.skip(n)) return std::nullopt;     // cipher suites
    if (!c.u8(n) || !c.skip(n)) return std::nullopt;      // compression methods
    if (!c.u16(n)) return std::nullopt;                   // extensions length
    Cursor ext(c.data(), std::min(n, c.left()));

    size_t type = 0, size = 0;
    while (ext.u16(type) && ext.u16(size)) {
        if (type == 0x0000) {                             // server_name
            Cursor sni(ext.data(), std::min(size, ext.left()));
            size_t listLen = 0, nameType = 0, nameLen = 0;
            if (!sni.u16(listLen) || !sni.u8(nameType) || !sni.u16(nameLen)) return std::nullopt;
            if (nameType != 0 || nameLen > sni.left()) return std::nullopt;
            return cleanName(std::string(reinterpret_cast<const char*>(sni.data()), nameLen));
        }
        if (!ext.skip(size)) break;
    }
    return std::nullopt;
}

std::optional<std::string> extractHttpHost(const uint8_t* payload, size_t length) {
    const std::string_view text(reinterpret_cast<const char*>(payload), length);
    bool isRequest = false;
    for (const char* method : {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS "})
        if (text.substr(0, std::strlen(method)) == method) isRequest = true;
    if (!isRequest) return std::nullopt;

    // Check header lines only, stopping at the blank line before the body.
    size_t pos = text.find('\n');
    while (pos != std::string_view::npos) {
        const size_t start = pos + 1;
        pos = text.find('\n', start);
        std::string_view line = text.substr(start, pos == std::string_view::npos ? pos : pos - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) break;
        if (line.size() < 5 || toLower(std::string(line.substr(0, 5))) != "host:") continue;
        line.remove_prefix(5);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) line.remove_suffix(1);
        return cleanName(std::string(line.substr(0, line.find(':'))));   // drop ":port"
    }
    return std::nullopt;
}

std::optional<std::string> extractDnsQuery(const uint8_t* payload, size_t length) {
    if (length < 12 || (payload[2] & 0x80) || readBE16(payload + 4) == 0)
        return std::nullopt;                              // too short, a response, or no question
    Cursor c(payload, length);
    c.skip(12);
    std::string name;
    size_t label = 0;
    while (c.u8(label)) {
        if (label == 0) return cleanName(name);
        if (label > 63 || label > c.left()) return std::nullopt;
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(c.data()), label);
        c.skip(label);
    }
    return std::nullopt;
}
