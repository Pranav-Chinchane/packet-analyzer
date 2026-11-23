#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include "packet_parser.h"

// Identifies a connection. Endpoints are sorted so that both directions
// (client -> server and server -> client) produce the same key.
struct FlowKey {
    IpAddress ipA, ipB;
    uint16_t portA = 0, portB = 0;
    uint8_t protocol = 0;

    bool operator==(const FlowKey& o) const {
        return ipA == o.ipA && ipB == o.ipB && portA == o.portA &&
               portB == o.portB && protocol == o.protocol;
    }
};

FlowKey makeFlowKey(const ParsedPacket& p);

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const;
};

enum class App {
    Unknown, HTTP, HTTPS, DNS, QUIC,
    Google, YouTube, Facebook, Instagram, WhatsApp, Twitter, Netflix, Amazon,
    Microsoft, Apple, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare,
    // Services, recognised by the server port once the server answers
    FTP, SSH, Telnet, Email, FileSharing, RemoteDesktop, Database, DHCP, NTP, MDNS,
    Count   // keep last
};

const char* appName(App app);
std::optional<App> appFromName(const std::string& name);   // case-insensitive

// Service usually found on this server port, if known.
std::optional<App> appFromPort(uint16_t serverPort, bool tcp);

// App owning this lower-case domain, if known.
std::optional<App> appFromDomain(const std::string& host);

// True for the domain itself and its subdomains. Both must be lower-case.
bool matchesDomain(const std::string& host, const std::string& domain);

std::string toLower(std::string s);
