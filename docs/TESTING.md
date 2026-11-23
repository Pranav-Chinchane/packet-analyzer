# Testing and performance

## Run the tests

Build first, then from the project folder:

```powershell
python tests\run_tests.py
python tests\test_ui_server.py
```

Each ends with the number of failures, which should be 0.

| File | What it tests |
|---|---|
| `tests/unit_tests.cpp` | Single parts: decoding, names, rules, the queue. Started by `run_tests.py` |
| `tests/run_tests.py` | Both programs on captures with known answers (166 tests) |
| `tests/test_ui_server.py` | The web server (23 tests) |

## What is checked

| Question | How |
|---|---|
| Are the answers right? | Generated captures with known contents |
| Do both programs agree? | Full reports compared; every case also repeated 100 times with different thread counts |
| Can packets get lost? | Workers are slowed on purpose; every packet must still be handled |
| Can bad data crash it? | Packets cut at every length, changed bytes, broken files |
| Are alerts correct? | Just below and exactly at each threshold, plus harmless lookalikes |
| Is the web server safe? | Requests from other sites, odd input, interrupted uploads |

## Checks made by hand during development

- **Wireshark's tshark:** packet counts and website names matched on the 8 public Ethernet captures tried.
- **Damaged captures:** 600 randomly changed files caused no crash.
- **Undefined-behaviour check:** passed on the unit tests and during the damaged-file runs.
- **Web page:** tried in Chrome from 320 to 1440 pixels wide.

- **Online version:** 17 captures, each with and without rules, gave the same report (or the same error) as the normal engine.

AddressSanitizer and ThreadSanitizer were not available on the development PC. The workflow in `.github/workflows` runs them on Linux, and they passed.

## Performance

Median of 5 runs on one Windows PC with 12 logical processors:

| Capture | `dpi_simple` | `dpi_mt` (default) | `dpi_mt --lbs 1 --fps 4` |
|---|---|---|---|
| 462,000 small packets | 354 ms | 274 ms | 224 ms |
| 943,500 larger packets | 1098 ms | 999 ms | 976 ms |

- Threads help most with many small packets. With larger ones, reading and writing the file takes most of the time.
- The first version passed packets between threads one at a time and was about four times **slower** than one thread. Passing batches of 256 fixed that.
- These were measured before the service labels were added. Your results will differ.

## Bugs that testing found

| Bug | Fix |
|---|---|
| Normal IPv6 reverse lookups raised a DNS alert | Names ending in `.arpa` are ignored |
| Replies in a capture that started late looked like a port scan | Only connections whose start was seen count |
| Two web servers could share one port on Windows | The second one now stops with a message |
| Half-finished uploads were analysed as complete | Upload length is checked |

## Technical limits

- TCP data is joined only for the HTTPS Client Hello, and only within one TLS record.
- A connection that reuses the same addresses and ports keeps its earlier label and blocked state.
- `dpi_mt` keeps packet order within a connection, but not between connections.
- The web page receives the 500 busiest connections and shows up to 200 at a time.
