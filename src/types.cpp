#include "types.h"
#include <array>
#include <utility>

FlowKey makeFlowKey(const ParsedPacket& p) {
    FlowKey k;
    k.protocol = p.protocol;
    const bool srcFirst = std::make_pair(p.srcIp, p.srcPort) <= std::make_pair(p.dstIp, p.dstPort);
    k.ipA = srcFirst ? p.srcIp : p.dstIp;
    k.portA = srcFirst ? p.srcPort : p.dstPort;
    k.ipB = srcFirst ? p.dstIp : p.srcIp;
    k.portB = srcFirst ? p.dstPort : p.srcPort;
    return k;
}

size_t FlowKeyHash::operator()(const FlowKey& k) const {
    // Mix every input bit into every output bit, because the engine uses
    // different parts of the hash for load balancers and workers.
    auto mix = [](uint64_t h) {
        h ^= h >> 33; h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ULL;
        return h ^ (h >> 33);
    };
    uint64_t h = 0;
    for (const IpAddress* ip : {&k.ipA, &k.ipB}) {
        uint64_t half[2];
        std::memcpy(half, ip->bytes.data(), 16);
        h = mix(mix(h ^ half[0]) ^ half[1]);
    }
    h = mix(h ^ ((uint64_t(k.portA) << 32) | (uint64_t(k.portB) << 8) | k.protocol));
    return static_cast<size_t>(h);
}

const char* appName(App app) {
    static constexpr std::array<const char*, static_cast<size_t>(App::Count)> names = {
        "Other", "HTTP", "HTTPS", "DNS", "QUIC",
        "Google", "YouTube", "Facebook", "Instagram", "WhatsApp", "Twitter/X", "Netflix", "Amazon",
        "Microsoft", "Apple", "Telegram", "TikTok", "Spotify", "Zoom", "Discord", "GitHub", "Cloudflare",
        "FTP", "SSH", "Telnet", "Email", "File sharing", "Remote desktop", "Database", "DHCP", "NTP", "mDNS"};
    return names[static_cast<size_t>(app)];
}

std::optional<App> appFromName(const std::string& name) {
    const std::string wanted = toLower(name);
    for (int i = 0; i < static_cast<int>(App::Count); i++) {
        const App app = static_cast<App>(i);
        if (toLower(appName(app)) == wanted) return app;
    }
    if (wanted == "twitter" || wanted == "x") return App::Twitter;
    return std::nullopt;
}

std::optional<App> appFromPort(uint16_t port, bool tcp) {
    switch (port) {
        case 67: case 68: case 546: case 547: if (!tcp) return App::DHCP; break;
        case 123: if (!tcp) return App::NTP; break;
        case 5353: if (!tcp) return App::MDNS; break;
        case 20: case 21: if (tcp) return App::FTP; break;
        case 22: if (tcp) return App::SSH; break;
        case 23: if (tcp) return App::Telnet; break;
        case 25: case 110: case 143: case 465: case 587: case 993: case 995: if (tcp) return App::Email; break;
        case 139: case 445: if (tcp) return App::FileSharing; break;
        case 3389: case 5900: if (tcp) return App::RemoteDesktop; break;
        case 1433: case 3306: case 5432: case 6379: case 27017: if (tcp) return App::Database; break;
        default: break;
    }
    return std::nullopt;
}

bool matchesDomain(const std::string& host, const std::string& domain) {
    if (host == domain) return true;
    return host.size() > domain.size() &&
           host.compare(host.size() - domain.size(), domain.size(), domain) == 0 &&
           host[host.size() - domain.size() - 1] == '.';
}

std::optional<App> appFromDomain(const std::string& host) {
    // First match wins, so list specific entries before general ones.
    static const std::pair<const char*, App> table[] = {
        {"yt3.ggpht.com", App::YouTube}, {"youtube.com", App::YouTube}, {"youtu.be", App::YouTube},
        {"ytimg.com", App::YouTube}, {"googlevideo.com", App::YouTube},
        {"google.com", App::Google}, {"googleapis.com", App::Google}, {"gstatic.com", App::Google},
        {"ggpht.com", App::Google}, {"gvt1.com", App::Google}, {"googleusercontent.com", App::Google},
        {"facebook.com", App::Facebook}, {"fbcdn.net", App::Facebook}, {"fb.com", App::Facebook},
        {"fbsbx.com", App::Facebook}, {"meta.com", App::Facebook},
        {"instagram.com", App::Instagram}, {"cdninstagram.com", App::Instagram},
        {"whatsapp.com", App::WhatsApp}, {"whatsapp.net", App::WhatsApp}, {"wa.me", App::WhatsApp},
        {"twitter.com", App::Twitter}, {"x.com", App::Twitter}, {"twimg.com", App::Twitter}, {"t.co", App::Twitter},
        {"netflix.com", App::Netflix}, {"nflxvideo.net", App::Netflix}, {"nflximg.net", App::Netflix},
        {"amazon.com", App::Amazon}, {"amazon.in", App::Amazon}, {"amazonaws.com", App::Amazon},
        {"cloudfront.net", App::Amazon},
        {"microsoft.com", App::Microsoft}, {"office.com", App::Microsoft}, {"office365.com", App::Microsoft},
        {"live.com", App::Microsoft}, {"outlook.com", App::Microsoft}, {"bing.com", App::Microsoft},
        {"msn.com", App::Microsoft}, {"azure.com", App::Microsoft}, {"windowsupdate.com", App::Microsoft},
        {"apple.com", App::Apple}, {"icloud.com", App::Apple}, {"mzstatic.com", App::Apple},
        {"telegram.org", App::Telegram}, {"t.me", App::Telegram},
        {"tiktok.com", App::TikTok}, {"tiktokcdn.com", App::TikTok}, {"bytedance.com", App::TikTok},
        {"spotify.com", App::Spotify}, {"scdn.co", App::Spotify},
        {"zoom.us", App::Zoom}, {"zoom.com", App::Zoom},
        {"discord.com", App::Discord}, {"discord.gg", App::Discord}, {"discordapp.com", App::Discord},
        {"github.com", App::GitHub}, {"githubusercontent.com", App::GitHub}, {"github.io", App::GitHub},
        {"cloudflare.com", App::Cloudflare},
    };
    for (const auto& [domain, app] : table)
        if (matchesDomain(host, domain)) return app;
    return std::nullopt;
}

std::string toLower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}
