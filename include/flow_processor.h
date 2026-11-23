#pragma once
// The heart of the engine: flow tracking + classification + blocking.
// The single-threaded program has one; each worker thread has its own.
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include "hello_buffer.h"
#include "packet_parser.h"
#include "pcap_format.h"
#include "rules.h"
#include "types.h"

// What is known about one connection. Kept for the reports.
struct FlowInfo {
    IpAddress clientIp, serverIp;          // client = the side that started it
    uint16_t clientPort = 0, serverPort = 0;
    uint8_t protocol = 0;
    App app = App::Unknown;
    std::string name;                      // host name, once seen
    std::string reason;                    // why it was blocked, or empty
    uint64_t packets = 0, bytes = 0, dropped = 0;
    bool opened = false;                   // the client's TCP SYN was seen first
    bool answered = false;                 // the server sent something
    bool plainHttp = false;                // an unencrypted web request was seen
};

struct Stats {
    struct Second { uint64_t forwarded = 0, dropped = 0; };

    uint64_t total = 0, bytes = 0, forwarded = 0, dropped = 0, unsupported = 0;
    uint64_t tcp = 0, udp = 0, flows = 0;
    std::map<App, uint64_t> appPackets;
    std::map<App, uint64_t> appDropped;
    std::map<std::string, App> names;
    std::map<std::string, uint64_t> blockedFlows;          // reason -> connections
    std::map<uint32_t, Second> timeline;                   // by timestamp second
    std::map<IpAddress, std::set<std::string>> dns;        // client -> names asked for
    std::vector<FlowInfo> connections;

    void add(Stats other);
    void countUnsupported(const Packet& packet);
};

class FlowProcessor {
public:
    explicit FlowProcessor(const Rules& rules) : rules_(rules) {}

    // True: forward the packet. False: drop it.
    bool process(const ParsedPacket& p, const Packet& packet);

    // Statistics including each flow's final label. Call once, after the last packet.
    Stats finish();

private:
    struct Flow {
        FlowInfo info;
        bool blocked = false;
        bool helloDone = false;
        bool seqKnown = false;                 // the client's SYN was seen
        uint32_t clientSeq = 0;                // its first data byte
        std::unique_ptr<HelloBuffer> hello;
    };

    void start(Flow& flow, const ParsedPacket& p);
    void classify(Flow& flow, const ParsedPacket& p, const uint8_t* payload);
    void findTlsName(Flow& flow, const ParsedPacket& p, const uint8_t* payload);
    void setName(Flow& flow, const std::string& name);

    const Rules& rules_;
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
    Stats stats_;
};
