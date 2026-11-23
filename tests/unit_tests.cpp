// Small self-contained unit tests (no framework). T-numbers match run_tests.py.
#include <atomic>
#include <cstdio>
#include <thread>
#include "dpi_engine.h"
#include "hello_buffer.h"
#include "name_extractor.h"
#include "thread_safe_queue.h"

static int failures = 0, checks = 0;
#define CHECK(x) do { checks++; if (!(x)) { failures++; std::printf("FAIL line %d: %s\n", __LINE__, #x); } } while (0)

using Bytes = std::vector<uint8_t>;

// Copy into an exactly sized heap block, so sanitizers see any over-read.
template <typename F>
static auto exact(const Bytes& b, size_t n, F f) {
    const Bytes cut(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n));
    return f(cut);
}

static void put16(Bytes& b, size_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}

static Bytes clientHello(const std::string& host, bool withSni = true) {
    Bytes ext;
    put16(ext, 0x2b); put16(ext, 3); ext.push_back(2); put16(ext, 0x0304);
    if (withSni) {
        put16(ext, 0); put16(ext, host.size() + 5); put16(ext, host.size() + 3);
        ext.push_back(0); put16(ext, host.size());
        ext.insert(ext.end(), host.begin(), host.end());
    }
    Bytes body = {3, 3};
    body.resize(34, 7);
    body.push_back(0);
    put16(body, 2); put16(body, 0x1301);
    body.push_back(1); body.push_back(0);
    put16(body, ext.size());
    body.insert(body.end(), ext.begin(), ext.end());
    Bytes out = {0x16, 3, 1};
    put16(out, body.size() + 4);
    out.push_back(1); out.push_back(0); put16(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

static Bytes tcpPacket(const Bytes& payload, size_t ipOptions = 0) {
    Bytes p(12, 2);
    put16(p, 0x0800);
    p.push_back(uint8_t(0x45 + ipOptions / 4)); p.push_back(0);
    put16(p, 40 + ipOptions + payload.size());
    put16(p, 1); put16(p, 0x4000);
    p.push_back(64); p.push_back(6); put16(p, 0);
    for (int x : {192, 168, 1, 100, 1, 2, 3, 4}) p.push_back(uint8_t(x));
    p.resize(p.size() + ipOptions, 1);
    put16(p, 50000); put16(p, 443);
    p.resize(p.size() + 8, 0);
    p.push_back(0x50); p.push_back(0x18);
    p.resize(p.size() + 6, 0);
    p.insert(p.end(), payload.begin(), payload.end());
    return p;
}

static void testParser() {
    ParsedPacket r;
    CHECK(parsePacket(tcpPacket({1, 2, 3}), r));
    CHECK(ipToString(r.srcIp) == "192.168.1.100" && ipToString(r.dstIp) == "1.2.3.4");
    CHECK(r.srcPort == 50000 && r.dstPort == 443 && r.payloadOffset == 54 && r.payloadLength == 3);
    CHECK(parsePacket(tcpPacket({9}, 8), r) && r.payloadOffset == 62 && r.payloadLength == 1);

    Bytes padded = tcpPacket({});                                        // T5
    padded.resize(padded.size() + 6, 0);
    CHECK(parsePacket(padded, r) && r.payloadLength == 0);

    Bytes fragment = tcpPacket({1});
    fragment[21] = 5;
    CHECK(!parsePacket(fragment, r));

    const Bytes full = tcpPacket(clientHello("a.com"), 4);               // T4
    for (size_t n = 0; n <= full.size(); n++)
        exact(full, n, [&](const Bytes& b) {
            if (parsePacket(b, r)) CHECK(r.payloadOffset + r.payloadLength <= b.size());
            return 0;
        });
    for (size_t i = 12; i < 60; i++)                                     // corrupt each header byte
        for (int v : {0, 1, 0x0f, 0x40, 0x4f, 0xff}) {
            Bytes bad = full;
            bad[i] = uint8_t(v);
            if (parsePacket(bad, r)) CHECK(r.payloadOffset + r.payloadLength <= bad.size());
        }
}

static void testNames() {
    auto sni = [](const Bytes& b) { return extractTlsSni(b.data(), b.size()); };
    CHECK(sni(clientHello("WWW.YouTube.com")) == "www.youtube.com");
    CHECK(!sni(clientHello("", false)));
    CHECK(!sni(clientHello("bad\x1b[31m.com")));                         // terminal escape rejected
    const Bytes hello = clientHello("www.youtube.com");                  // T7
    for (size_t n = 0; n < hello.size(); n++) CHECK(!exact(hello, n, sni));
    for (size_t i = 0; i < hello.size(); i++)
        for (int v : {0, 1, 0x7f, 0xff}) {
            Bytes bad = hello;
            bad[i] = uint8_t(v);
            exact(bad, bad.size(), sni);
        }

    auto http = [](const std::string& s) { return extractHttpHost(reinterpret_cast<const uint8_t*>(s.data()), s.size()); };
    CHECK(http("GET / HTTP/1.1\r\nhOsT:  Example.com:8080 \r\n\r\n") == "example.com");
    CHECK(!http("GET / HTTP/1.1\r\nA: b\r\n\r\nHost: body.com\r\n"));
    CHECK(!http("GET / HTTP/1.1\r\nX-Host: no.com\r\n\r\n"));
    CHECK(!http("hello"));
    const std::string req = "GET / HTTP/1.1\r\nHost: a.com\r\n\r\n";
    for (size_t n = 0; n <= req.size(); n++) http(req.substr(0, n));

    const Bytes dns = {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'x', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    auto q = [](const Bytes& b) { return extractDnsQuery(b.data(), b.size()); };
    CHECK(q(dns) == "x.com");
    for (size_t n = 0; n < 19; n++) CHECK(!exact(dns, n, q));
    Bytes response = dns;
    response[2] |= 0x80;
    CHECK(!q(response));
}

static void testTypesAndRules() {
    CHECK(appFromDomain("www.netflix.com") == App::Netflix);             // T6
    CHECK(appFromDomain("www.microsoft.com") == App::Microsoft);
    CHECK(appFromDomain("api.x.com") == App::Twitter);
    CHECK(appFromDomain("yt3.ggpht.com") == App::YouTube);
    CHECK(!appFromDomain("notgoogle.com"));
    CHECK(appFromPort(22, true) == App::SSH && !appFromPort(22, false) && !appFromPort(9999, true));
    CHECK(matchesDomain("x.com", "x.com") && !matchesDomain("netflix.com", "x.com"));
    for (int i = 0; i < static_cast<int>(App::Count); i++)
        CHECK(appFromName(appName(static_cast<App>(i))) == static_cast<App>(i));
    for (const char* ok : {"192.168.1.50", "2001:db8::1", "::", "::1", "fe80::1:0:0:2", "1:2:3:4:5:6:7:8"})
        CHECK(parseIp(ok) && ipToString(*parseIp(ok)) == ok);
    CHECK(ipToString(*parseIp("2001:DB8:0:0:0:0:0:1")) == "2001:db8::1");
    for (const char* bad : {":", "1:2", "1::2::3", "12345::", "::g", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::8", ":1:2:3:4:5:6:7:8"}) CHECK(!parseIp(bad));
    CHECK(parseIp("10.1.2.3")->isPrivate() && parseIp("fd00::1")->isPrivate() && !parseIp("8.8.8.8")->isPrivate() && !parseIp("2001:db8::1")->isPrivate());
    for (const char* bad : {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1..2.3", "a.b.c.d", "1.2.3.4 "}) CHECK(!parseIp(bad));

    ParsedPacket out, back;
    out.srcIp = IpAddress::fromV4(9); out.dstIp = IpAddress::fromV4(5); out.srcPort = 50000; out.dstPort = 443; out.protocol = 6;
    back.srcIp = IpAddress::fromV4(5); back.dstIp = IpAddress::fromV4(9); back.srcPort = 443; back.dstPort = 50000; back.protocol = 6;
    CHECK(makeFlowKey(out) == makeFlowKey(back));
    CHECK(FlowKeyHash{}(makeFlowKey(out)) == FlowKeyHash{}(makeFlowKey(back)));

    Rules r;
    CHECK(r.blockDomain("FaceBook.com") && r.blockApp("youtube") && r.blockIp("0.0.0.9"));
    CHECK(!r.blockDomain("") && !r.blockDomain("a b") && !r.blockApp("nope") && !r.blockIp("x"));
    FlowKey k;
    CHECK(r.check(k, App::HTTPS, "m.facebook.com") && !r.check(k, App::HTTPS, "notfacebook.com"));
    CHECK(r.check(k, App::YouTube, "") && !r.check(k, App::HTTPS, ""));
    k.ipB = IpAddress::fromV4(9);
    CHECK(r.check(k, App::HTTPS, "").has_value());
}

static void testHelloBuffer() {
    const Bytes hello = clientHello("www.youtube.com");
    auto name = [](const HelloBuffer& b) { return extractTlsSni(b.data().data(), b.data().size()); };
    for (uint32_t base : {1000u, 0xFFFFFFF0u})                           // also across sequence wrap-around
        for (size_t cut = 1; cut < hello.size(); cut++) {
            const uint32_t second = base + uint32_t(cut);
            HelloBuffer ordered(base), swapped(base), repeated(base);
            ordered.add(base, hello.data(), cut);
            CHECK(!ordered.finished());
            ordered.add(second, hello.data() + cut, hello.size() - cut);
            swapped.add(second, hello.data() + cut, hello.size() - cut);
            swapped.add(base, hello.data(), cut);
            repeated.add(base, hello.data(), cut);
            repeated.add(base, hello.data(), cut);
            repeated.add(base, hello.data(), hello.size());
            for (const HelloBuffer* b : {&ordered, &swapped, &repeated}) CHECK(b->finished() && name(*b) == "www.youtube.com");
        }
    HelloBuffer other(5);
    const uint8_t text[] = {'G', 'E', 'T'};
    other.add(5, text, 3);
    CHECK(other.finished());
}

static void testQueue() {                                                // T16
    ThreadSafeQueue<int> q(1000);
    std::atomic<long long> count{0}, sum{0};
    std::vector<std::thread> producers, consumers;
    for (int i = 0; i < 4; i++)
        consumers.emplace_back([&] { while (auto v = q.pop()) { count++; sum += *v; } });
    for (int i = 0; i < 4; i++)
        producers.emplace_back([&, i] { for (int k = 0; k < 250000; k++) q.push(i * 250000 + k); });
    for (auto& t : producers) t.join();
    q.close();
    for (auto& t : consumers) t.join();
    CHECK(count == 1000000 && sum == 499999500000LL);
    CHECK(!q.push(1));
}

static void testSlowWorkers(const char* sample, const char* output) {    // T18
    EngineConfig c;
    c.input = sample;
    c.output = output;
    c.testDelayMs = 20;
    const EngineResult r = runEngine(c, Rules{});
    CHECK(r.error.empty() && r.stats.total == 77 && r.stats.forwarded == 77);
}

int main(int argc, char** argv) {
    testParser();
    testNames();
    testTypesAndRules();
    testHelloBuffer();
    testQueue();
    if (argc == 3) testSlowWorkers(argv[1], argv[2]);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
