# Understand this project

> To run it first, follow the [README](../README.md).

**Lessons:** [1 Reading the file](#lesson-1-reading-the-file) · [2 Decoding](#lesson-2-decoding-a-packet) · [3 Flows](#lesson-3-grouping-packets-into-flows) · [4 Names](#lesson-4-finding-the-name) · [5 Rules](#lesson-5-rules) · [6 Insights](#lesson-6-insights) · [7 Threads](#lesson-7-threads) · [8 Web page](#lesson-8-the-web-page) · [Exercises](#exercises) · [Can you explain it?](#can-you-explain-it)

Read this with the code open. Each lesson says what to read, what to try, and how to check that you understood. It takes about a week at one or two hours a day.

## The whole project in one picture

```
capture file            C++ engine                                        results
.pcap / .pcapng  ->  read -> decode -> group -> name -> rules  ->  filtered .pcap
                     lesson 1  2        3        4       5         terminal report
                                                  |                JSON -> web page
                                                  +-> insights     lessons 6 and 8
                     lesson 7 runs steps 3-5 on several threads
```

**In one sentence:** it reads recorded network traffic, works out which app each connection belongs to, removes what you block, and explains what it saw.

## Words you need

| Word | Meaning |
|---|---|
| Packet | One small piece of network data |
| Header | Addressing information at the front of a packet |
| Payload | The data after the headers |
| IP address | Identifies a machine |
| Port | Identifies a program or service on a machine (443 = HTTPS, 53 = DNS) |
| Flow (connection) | All packets between the same two address-and-port pairs |
| TCP / UDP | TCP numbers its bytes and resends lost data; UDP just sends |
| TLS | The encryption used by HTTPS |
| Client Hello | The first TLS message, sent before encryption starts |
| SNI | The website name inside the Client Hello |
| Thread | Part of a program that runs at the same time as other parts |

---

## Lesson 1: reading the file

**Read:** [pcap_format.h](../include/pcap_format.h), [pcap_reader.cpp](../src/pcap_reader.cpp)

A `.pcap` file has one 24-byte header, then for each packet a 16-byte header and the packet bytes. A `.pcapng` file is a list of blocks: `[type][length][content][length again]`. Unknown block types are skipped.

**Byte order.** The number 1 in four bytes can be stored `00 00 00 01` (big-endian) or `01 00 00 00` (little-endian). The file starts with a known "magic" number; if it looks reversed, every number in the file must be swapped.

**Why check lengths?** A damaged file could claim a packet is 4 GB. The reader refuses anything above 262,144 bytes.

**Try:** open `data/test_dpi.pcap` in a hex viewer. The first four bytes are `d4 c3 b2 a1`, which is `0xa1b2c3d4` in little-endian.

**Check yourself:** why does the filtered file always use this computer's byte order? *(Because the numbers were already converted while reading.)*

## Lesson 2: decoding a packet

**Read:** [byte_order.h](../include/byte_order.h), [packet_parser.cpp](../src/packet_parser.cpp)

A packet is like nested envelopes:

```
Ethernet (14 bytes) -> IP (IPv4: 20-60, IPv6: 40 or more) -> TCP (20-60) or UDP (8) -> payload
```

Worked example, an IPv4 packet with normal header sizes:

| Byte | Value | Meaning |
|---|---|---|
| 12-13 | `08 00` | IPv4 (`86 dd` is IPv6, `81 00` is a VLAN tag) |
| 14 | `45` | version 4; header = 5 x 4 = 20 bytes |
| 23 | `06` | TCP (`11` hex is UDP) |
| 26-29 | `c0 a8 01 64` | from 192.168.1.100 |
| 34-35 | `c3 51` | source port 50001 |
| 36-37 | `01 bb` | destination port 443 |
| 54 onward | | payload |

Every read is checked against the packet's length, because captures can be damaged or malicious.

**Try:** convert `c3 51` yourself: 0xc3 = 195, so 195 x 256 + 0x51 (81) = 50001.

**Check yourself:** why is the IP length used instead of the packet size? *(Ethernet pads short packets; padding is not data.)*

## Lesson 3: grouping packets into flows

**Read:** [ip_address.h](../include/ip_address.h), [types.cpp](../src/types.cpp) (`makeFlowKey`, `FlowKeyHash`)

A flow is identified by two addresses, two ports and the protocol. Request and reply have source and destination swapped, so `makeFlowKey` **sorts the two ends**. Both directions then give the same key.

The flow table is an `unordered_map`, a hash table: finding a flow takes about the same time with ten flows or a million.

IPv4 addresses are stored inside IPv6's format (`::ffff:a.b.c.d`), so one type serves both.

**Check yourself:** what goes wrong without sorting? *(Replies become a different flow, so a blocked site's replies still pass.)*

## Lesson 4: finding the name

**Read:** [name_extractor.cpp](../src/name_extractor.cpp), [hello_buffer.cpp](../src/hello_buffer.cpp), `classify` in [flow_processor.cpp](../src/flow_processor.cpp)

1. **Guess from the port:** 443 means HTTPS, 80 HTTP, 53 DNS. Others such as 22 (SSH) count only after the server answers (`appFromPort`). If nothing matches, the label is **Other**.
2. **Look for a name:** SNI in TLS, `Host:` in HTTP, or the question in DNS.
3. **Map the name to an app:** `appFromDomain` in types.cpp.

HTTPS is encrypted, but the Client Hello comes first and normally shows the site name, so the server knows which certificate to send. **Nothing is decrypted.**

**Cursor.** The TLS message is a chain of "length, then that many bytes". The `Cursor` class refuses to step past the end, so a false length cannot cause an invalid read.

**Split messages.** A large Client Hello spans several packets, which may arrive out of order or twice. TCP numbers every byte, so `HelloBuffer` joins them by sequence number.

```
expected next: 1000
segment 1060 arrives early  -> keep for later
segment 1000 (60 bytes)     -> append, next = 1060
kept segment 1060           -> now fits, append
```

**Domain matching.** `netflix.com` contains the text `x.com`. So a match needs the same name, or an ending that starts after a dot.

**Try:** add Twitch. Put `Twitch` just before `Count` in `enum class App` (types.h), `"Twitch"` at the end of the name list, and `{"twitch.tv", App::Twitch}` in the table (types.cpp). Rebuild and run the tests.

## Lesson 5: rules

**Read:** [rules.cpp](../src/rules.cpp), `process` in [flow_processor.cpp](../src/flow_processor.cpp)

Checks in order: IP address, app, domain. When a rule matches, the **whole flow** is blocked from that packet on, in both directions. The handshake has already passed, because the name was not known yet. An IP rule matches from the first packet.

**Try:**

```powershell
.\build\dpi_simple.exe data\test_dpi.pcap build\out.pcap --block-app YouTube
```

Four YouTube packets, one dropped. **Check yourself:** why only one? *(Three handshake packets came before the name.)*

## Lesson 6: insights

**Read:** [insights.cpp](../src/insights.cpp)

| Alert | Rule | Why |
|---|---|---|
| Possible port scan | One machine tries 15 or more TCP ports on another | Attackers look for open services |
| Possible network scan | One machine tries one port on 20 or more machines with no answer | Looking for victims |
| Unusual DNS activity | 10 or more long names under one domain, from one machine | Data can be hidden in DNS names |
| Unencrypted login | FTP or Telnet was used and answered | Passwords can be read |
| Unencrypted web traffic | An HTTP request was seen | Anyone on the path can read it |

Two normal situations are left out on purpose: reverse DNS lookups (names ending in `.arpa`), and connections that were already open when the capture started. A test found that both caused false alarms.

These are simple rules. They **can be wrong in both directions**, so the wording is "possible".

**Check yourself:** name a harmless cause of a "port scan" alert. *(For example, an administrator checking a server.)*

## Lesson 7: threads

**Read in order:** [thread_safe_queue.h](../include/thread_safe_queue.h), [fast_path.cpp](../src/fast_path.cpp), [load_balancer.cpp](../src/load_balancer.cpp), [dpi_engine.cpp](../src/dpi_engine.cpp)

```
reader -> load balancers -> workers -> writer
```

| Idea | Why |
|---|---|
| A flow always goes to the same worker | Each worker owns its flow table, so no lock is needed |
| Queues have a maximum size | If workers are slow, the reader waits instead of filling memory |
| Packets travel in batches of 256 | Locking once per packet cost more than the work itself |
| The balancer uses `hash / lbCount` | Reusing `hash % n` would send everything to the same workers |
| Stop in order: balancers, workers, writer | Each stage empties before the next one closes, so nothing is lost |

`pop()` returns "nothing" only when the queue is closed **and** empty. That rule is what prevents lost packets.

Both programs use the same `FlowProcessor`. The tests compare their complete reports.

**Try:** run `dpi_mt` with `--lbs 1 --fps 4` and compare the worker counts.

## Lesson 8: the web page

**Read:** [server.py](../ui/server.py), then the script in [index.html](../ui/index.html)

1. The browser sends the file and the rules to the Python server.
2. The server runs the C++ program with `--json`.
3. The program writes JSON; the server returns it and the page draws it.

| Protection | Against |
|---|---|
| Listens on 127.0.0.1 only | Other computers connecting |
| Checks `Host` and `Origin` | Other websites using your server through your browser |
| Arguments passed as a list, no shell | Command injection |
| `textContent`, never HTML | Names containing scripts |
| Size limits | Very large uploads and rule lists |

---

## Which file does what

| File | Job |
|---|---|
| `pcap_reader`, `pcap_writer`, `pcap_format.h` | Capture files |
| `byte_order.h`, `ip_address`, `packet_parser` | Decoding |
| `types` | Flow key, app list, domain table |
| `name_extractor`, `hello_buffer` | Finding names |
| `rules` | Blocking |
| `flow_processor` | Joins all of the above for each packet |
| `insights`, `report` | Summary, alerts, devices; text and JSON output |
| `cli`, `main_simple`, `main_mt` | Command line and programs |
| `thread_safe_queue.h`, `fast_path`, `load_balancer`, `dpi_engine` | Threads |

## Exercises

1. **Easy:** add an app (lesson 4).
2. **Easy:** change `SCAN_PORTS` to 5, rebuild, and see which tests change.
3. **Medium:** add an alert for Remote Desktop (port 3389), modelled on FTP.
4. **Medium:** add `--block-port`.
5. **Hard:** support raw IP captures (link type 101).

After each one, run `python tests\run_tests.py`.

## Can you explain it?

You understand the project when you can answer these without notes:

1. How is the site name visible in HTTPS?
2. Why sort the two ends of a flow?
3. What happens to a packet at every step?
4. How are split Client Hellos handled?
5. Why does a worker not need a lock for its flows?
6. How does the program stop without losing packets?
7. Why are packets sent in batches?
8. What can it not detect? *(See Limits in the README.)*
