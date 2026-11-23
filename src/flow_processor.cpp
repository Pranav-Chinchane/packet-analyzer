#include "flow_processor.h"
#include <iterator>
#include <optional>
#include "name_extractor.h"

void Stats::add(Stats o) {
    total += o.total;
    bytes += o.bytes;
    forwarded += o.forwarded;
    dropped += o.dropped;
    unsupported += o.unsupported;
    tcp += o.tcp;
    udp += o.udp;
    flows += o.flows;
    for (const auto& [app, n] : o.appPackets) appPackets[app] += n;
    for (const auto& [app, n] : o.appDropped) appDropped[app] += n;
    for (const auto& [name, app] : o.names) names.emplace(name, app);
    for (const auto& [why, n] : o.blockedFlows) blockedFlows[why] += n;
    for (const auto& [second, n] : o.timeline) {
        timeline[second].forwarded += n.forwarded;
        timeline[second].dropped += n.dropped;
    }
    for (auto& [ip, asked] : o.dns) dns[ip].merge(asked);
    connections.insert(connections.end(), std::make_move_iterator(o.connections.begin()),
                       std::make_move_iterator(o.connections.end()));
}

void Stats::countUnsupported(const Packet& packet) {
    total++;
    forwarded++;
    unsupported++;
    bytes += packet.data.size();
    timeline[packet.tsSec].forwarded++;
}

// The first packet decides which side is the client.
void FlowProcessor::start(Flow& flow, const ParsedPacket& p) {
    const bool tcpSyn = p.protocol == PROTO_TCP && (p.tcpFlags & TCP_SYN);
    const bool synAck = tcpSyn && (p.tcpFlags & TCP_ACK);
    const bool fromServer = synAck || (!tcpSyn && p.srcPort < 1024 && p.dstPort >= 1024);
    FlowInfo& i = flow.info;
    i.protocol = p.protocol;
    i.opened = tcpSyn && !synAck;
    i.clientIp = fromServer ? p.dstIp : p.srcIp;
    i.clientPort = fromServer ? p.dstPort : p.srcPort;
    i.serverIp = fromServer ? p.srcIp : p.dstIp;
    i.serverPort = fromServer ? p.srcPort : p.dstPort;
}

void FlowProcessor::setName(Flow& flow, const std::string& name) {
    flow.info.name = name;
    // Report one label per name, whichever protocol (or thread) saw it first.
    stats_.names.emplace(name, appFromDomain(name).value_or(App::Unknown));
}

void FlowProcessor::findTlsName(Flow& flow, const ParsedPacket& p, const uint8_t* payload) {
    if (p.tcpFlags & TCP_SYN) {
        flow.seqKnown = true;
        flow.clientSeq = p.tcpSeq + 1;           // the SYN itself uses one number
        return;
    }
    if (flow.helloDone || p.payloadLength == 0) return;
    if (!flow.hello) flow.hello = std::make_unique<HelloBuffer>(flow.seqKnown ? flow.clientSeq : p.tcpSeq);
    flow.hello->add(p.tcpSeq, payload, p.payloadLength);
    const auto& data = flow.hello->data();
    const auto name = extractTlsSni(data.data(), data.size());
    if (name) {
        setName(flow, *name);
        flow.info.app = appFromDomain(*name).value_or(flow.info.app);
    }
    if (name || flow.hello->finished()) {
        flow.helloDone = true;
        flow.hello.reset();
    }
}

void FlowProcessor::classify(Flow& flow, const ParsedPacket& p, const uint8_t* payload) {
    FlowInfo& i = flow.info;
    const bool tcp = p.protocol == PROTO_TCP;
    auto usesPort = [&](uint16_t port) { return p.srcPort == port || p.dstPort == port; };

    if (usesPort(53)) {
        i.app = App::DNS;
        // One DNS flow may carry several queries, so look at each of them.
        if (!tcp) {
            if (auto name = extractDnsQuery(payload, p.payloadLength)) {
                setName(flow, *name);
                stats_.dns[p.srcIp].insert(*name);
            }
        }
        return;
    }
    if (i.app == App::Unknown) {                 // first guess: the port
        if (usesPort(443)) i.app = tcp ? App::HTTPS : App::QUIC;
        else if (tcp && usesPort(80)) i.app = App::HTTP;
        // An unanswered attempt proves nothing, so TCP services need a reply.
        else if (!tcp || i.answered) i.app = appFromPort(i.serverPort, tcp).value_or(App::Unknown);
    }
    if (!i.name.empty() || !tcp) return;         // already named
    if (p.dstPort == 443) {                      // better: the host name
        findTlsName(flow, p, payload);
    } else if (p.dstPort == 80) {
        if (auto name = extractHttpHost(payload, p.payloadLength)) {
            setName(flow, *name);
            i.app = appFromDomain(*name).value_or(i.app);
            i.plainHttp = true;
        }
    }
}

bool FlowProcessor::process(const ParsedPacket& p, const Packet& packet) {
    const FlowKey key = makeFlowKey(p);
    Flow& flow = flows_[key];
    FlowInfo& i = flow.info;
    if (i.packets == 0) start(flow, p);
    i.packets++;
    i.bytes += packet.data.size();
    if (p.srcPort == i.serverPort && p.srcIp == i.serverIp) i.answered = true;
    stats_.total++;
    stats_.bytes += packet.data.size();
    (p.protocol == PROTO_TCP ? stats_.tcp : stats_.udp)++;

    // Blocked flows are still identified, so reports show what was blocked.
    classify(flow, p, packet.data.data() + p.payloadOffset);
    if (!flow.blocked) {
        if (auto reason = rules_.check(key, i.app, i.name)) {
            flow.blocked = true;
            i.reason = *reason;
            stats_.blockedFlows[*reason + (i.name.empty() ? "" : " (" + i.name + ")")]++;
        }
    }
    auto& second = stats_.timeline[packet.tsSec];
    if (flow.blocked) {
        i.dropped++;
        stats_.dropped++;
        second.dropped++;
    } else {
        stats_.forwarded++;
        second.forwarded++;
    }
    return !flow.blocked;
}

Stats FlowProcessor::finish() {
    stats_.flows = flows_.size();
    stats_.connections.reserve(flows_.size());
    for (auto& [key, flow] : flows_) {
        stats_.appPackets[flow.info.app] += flow.info.packets;
        if (flow.info.dropped) stats_.appDropped[flow.info.app] += flow.info.dropped;
        stats_.connections.push_back(std::move(flow.info));
    }
    flows_.clear();
    return std::move(stats_);
}
