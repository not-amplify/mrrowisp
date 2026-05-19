# mrrowisp Hardening — Design Spec

**Date:** 2026-05-19
**Status:** Approved (pending user review of this written doc)
**Author:** OpenCode (with user, Amplify)

## Background

mrrowisp is a Wisp v1/v2 protocol server (TCP/UDP multiplexed over WebSocket) written in Go. It accepts WebSocket connections from clients, decodes Wisp frames, and on `CONNECT` packets dials arbitrary `host:port` destinations on the client's behalf — effectively an open proxy.

OVHcloud has issued two abuse tickets confirming that mrrowisp (and other Wisp implementations) is being abused to source TCP SYN floods:

- **Ticket 678956 (May 7, source `15.204.247.101`):** 22 Kpps / 11 Mbps and 19 Kpps / 9 Mbps SYN-only bursts to `153.75.225.178:81`.
- **Ticket 680426 (May 11, source `15.204.116.230`):** 31 Kpps / 15 Mbps SYN-only bursts to `153.75.225.178:81`. Edge-firewall blocking the actor's source IP did not stop the attack.

The attack pattern: the actor instructs the Wisp server (via thousands of legitimate `CONNECT` packets) to open TCP connections to a chosen victim. The server obediently issues real SYNs from its own interface. The victim either silently drops or RSTs the SYN-ACKs, so the connections never complete — OVH's egress detector sees SYN-only outbound traffic and attributes the attack to the Wisp host. The actor's goal is dual: stress the victim, and trigger OVH to suspend the Wisp host.

A separate vector the user described: client-side script on a popular attacker-controlled website drives many residential IPs (each opening a moderate number of WS connections) at the same victim — a distributed version of the same abuse that defeats simple per-source-IP rate limits.

## Goals

1. **Eliminate the SYN-flood / TCP-amplification abuse vector** via per-destination rate caps, SYN-flood signature detection, and a destination reputation system.
2. **Close SSRF** (private-range egress) by default with a configurable allow-list.
3. **Build a reputation store** that flags suspect source IPs and destination targets, persisted across restarts, without binary-banning legitimate-looking residential IPs.
4. **Fix remaining critical and high findings** from the security review (see Appendix A).
5. **Backwards-compatible**: new behavior is gated by config; defaults are safe.

## Non-goals

- Not adding TLS termination in this PR (deployment concern; document recommended reverse-proxy setup).
- Not rewriting the hand-rolled WebSocket frame reader (only fixing its bugs: unbounded payload, deflate inconsistency, unsafe-pointer mask XOR).
- Not redesigning Twisp's command protocol; locking it behind required-auth is the realistic fix.
- Not adding a structured logger framework (`zap`, `slog`) — emit JSON-shaped lines via `log.Printf` for compatibility.

## Architecture

### New files

- `wisp/limits.go` — concurrency caps and sliding-window rate limiters.
- `wisp/egress.go` — IP-policy evaluator (private-range detection + CIDR allow/deny).
- `wisp/reputation.go` — source/destination reputation store with persistence.
- `wisp/signature.go` — SYN-flood signature detector (per-WS, per-destination).
- `wisp/clientip.go` — extracts source IP from `*http.Request` with trusted-proxy header support.
- `wisp/limits_test.go`, `wisp/egress_test.go`, `wisp/reputation_test.go`, `wisp/signature_test.go`, `wisp/wsreader_test.go`, `wisp/v2_test.go` — unit tests.

### Modified files

- `main.go` — new `FloodProtection`, `Reputation`, `Egress`, `TrustedProxies` config sub-structs; switch to file-only `-config` flag (deprecate JSON-string form); HTTP server gains `ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout`.
- `wisp/wisp.go` — `Config` gains new sub-structs and pointers to the global limiter / reputation store; `CreateWispHandler` initializes them.
- `wisp/wisp-connection.go` — `wispConnection` carries source IP and a reference to global limiters/reputation; `handleConnectPacket` runs the full enforcement pipeline (see flow below); fixes the `close(writeCh)` race using `sync.Once` + done channel instead of `recover()`.
- `wisp/wisp-stream.go` — after DNS resolution, runs egress policy on every resolved IP, picks the first allowed; acquires the in-flight SYN semaphore around `Dial`; records dial outcome to the signature detector and reputation store.
- `wisp/wsreader.go` — caps `payloadLen` at `MaxPayloadSize` (default 1 MiB, configurable); replaces unsafe-pointer `maskXOR` with safe word-loop using `binary.LittleEndian`; documents `permessage-deflate` is unsupported and returns config error if enabled.
- `wisp/v2.go` — `subtle.ConstantTimeCompare` for password compare; optional bcrypt support (`$2a$`/`$2b$` prefix); plaintext logged as deprecated.
- `wisp/twisp.go` — refuses `streamTypeTerm` unless `enableTwisp: true` AND `(passwordAuthRequired || certAuthRequired)` AND `authPassed == true`. Logs every twisp attempt to reputation store.
- `src/server/index.ts` — replaces argv config-passing with a temp file (`0600` perms); reuses one `WebSocketServer` in `route()`; fixes `dnsServer`/`dnsServers` schema mismatch; adds builder methods + types for new config blocks.
- `example.config.json`, `README.md` — document new config.

### Data flow: CONNECT packet (post-change)

```
client → CONNECT(streamId, type, port, hostname)
  │
  ├─ resolve source IP (clientip.go)
  │
  ├─ per-WS connectRateLimiter.allow()            ─ throttled? close stream + score+5
  ├─ perConn.concurrentStreams < cap              ─ over? close + score+5
  ├─ perSourceIP slidingWindow.allow(srcIP)       ─ throttled? close + score+5
  ├─ reputation.source[srcIP].score >= strict?    ─ if dst already flagged, refuse + score+2
  │
  ├─ hostname is IP literal?
  │     └─ egress.evaluate(ip)                    ─ blocked? close + score+15 + dest+20
  ├─ DNS resolve (cached)
  │     └─ for each resolved IP:
  │             egress.evaluate(ip)               ─ pick first allowed
  │             if none allowed:                  ─ close + score+15 + dest+20
  │
  ├─ perDest slidingWindow.allow(dstIP, dstPort)  ─ throttled? close + score+5 + dest+5
  ├─ reputation.dest[dstIP:dstPort].score >= strict?
  │     └─ refuse + score+2 + dest+1
  │
  ├─ signature.observeConnect(srcIP, dstIP, dstPort, now)
  │     │  (records the attempt; outcome added later)
  │
  ├─ inFlightSyns.acquire()                       ─ would block? close + score+5
  │
  ├─ violationCounter >= wsCloseAfterViolations?  ─ close ENTIRE WS, score+10
  │
  └─ Dial → on return:
        ├─ inFlightSyns.release()
        ├─ signature.observeOutcome(streamId, success)
        ├─ if signature.match(srcIP, dstKey):     ─ score+25, dest+30, close WS
        └─ if success and stream long-lived:      ─ score-2 (good-actor decay)
```

### Reputation store

- **Two tables:** `sources` keyed by source IP string, `destinations` keyed by `"ip:port"` string.
- **Each entry:**
  - `score` (int, clamped 0..100)
  - `lastSeen` (RFC3339)
  - `firstSeen` (RFC3339)
  - `events` (map[reason]count)
  - `distinctSources` (destinations only; counts unique srcIPs observed since `firstSeen`)
- **Decay:** background goroutine ticks every 5 minutes, subtracts `scoreDecayPerHour * elapsedHours` from every entry's score, clamps to 0. Entries with `score < 5 && lastSeen > evictAfterDays` are removed.
- **Persistence:** every `saveIntervalSeconds`, snapshot the maps under a read lock, write to `storePath + ".tmp"`, `fsync`, `rename` to `storePath`. Atomic. Survives kill -9.
- **Hot path:** all mutations go through `Add(srcIP, reason, weight)` and `AddDest(dstIP, dstPort, reason, weight, srcIP)`. These methods hold the write lock only for the table mutation; persistence happens in a separate goroutine reading a snapshot.
- **Read API:** `Score(srcIP) int`, `DestScore(ip, port) int`, `Tier(score) Tier`. Tier is `Normal | Warn | Throttle | Strict`.

### SYN-flood signature detector

- **Per (`wispConnection`, `dstIP:dstPort`) tuple**, sliding window of last `windowMs` milliseconds of dial attempts. Each attempt has an outcome bit: `success` (handshake completed) or `failure` (refused/timeout/RST/closed-before-bytes).
- **Match condition:** ≥ `minSamples` attempts in the window AND failed/total ≥ `failedHandshakeRatio`.
- **Cheaply approximated:** ring buffer of `minSamples` entries per tuple (default 32 entries × 8 bytes = 256 B per active tuple, garbage-collected when the WS closes).
- **On match:** add `synSignature` event to source AND destination; close the WebSocket with `closeReasonBlocked`.
- **Why per-WS not global:** global match would conflate multiple legitimate clients targeting a slow but healthy server. Per-WS keeps it surgical.
- **Destination global escalation:** when ≥ K distinct sources have produced a `synSignature` event against the same destination within the last hour, the destination's score jumps to `strict`. This catches the distributed-residential-IPs attack.

### Egress policy

```go
func (p *egressPolicy) Evaluate(ip net.IP) (allowed bool, reason string)
```

Order of checks:
1. `denyIPs` exact match → deny.
2. `denyCIDRs` → deny.
3. `allowIPs` exact match → allow (overrides private-range check).
4. `allowCIDRs` → allow (overrides private-range check).
5. `ip.IsUnspecified()` (0.0.0.0, ::) → deny.
6. `ip.IsLoopback()` → deny unless `allowPrivate`.
7. `ip.IsPrivate()` (RFC1918, ULA fc00::/7) → deny unless `allowPrivate`.
8. `ip.IsLinkLocalUnicast()` / `ip.IsLinkLocalMulticast()` → deny unless `allowPrivate`.
9. `ip.IsMulticast()` (other) → deny.
10. IPv4-mapped IPv6 (`::ffff:0:0/96`) → unwrap and re-evaluate as v4.
11. Default: allow.

Reasons returned: `"deny_ip"`, `"deny_cidr"`, `"unspecified"`, `"loopback"`, `"private"`, `"link_local"`, `"multicast"`.

### Source-IP extraction

```go
func ResolveClientIP(r *http.Request, trustedProxies []net.IPNet, headers []string) net.IP
```

- Parse `r.RemoteAddr` → immediate peer.
- If peer ∈ `trustedProxies`, walk `headers` in order; the first non-empty header is parsed (rightmost-trustworthy IP for `X-Forwarded-For`, single value for `CF-Connecting-IP`).
- Else, return peer IP.
- Always returns a non-nil `net.IP` (falls back to `0.0.0.0` if everything fails; that IP is treated as "unknown" and gets a special bucket in reputation).

### Config schema (new + revised)

```jsonc
{
  "port": 6001,
  "disableUDP": false,
  // ... existing fields unchanged ...

  "trustedProxies": [],           // []string of IPs/CIDRs; empty = trust nobody, use RemoteAddr only
  "trustedHeaders": ["CF-Connecting-IP", "X-Forwarded-For"],

  "maxPayloadBytes": 1048576,     // 1 MiB cap on a single WS frame payload (was unbounded)

  "floodProtection": {
    "enabled": true,
    "maxConnectsPerSourceIPPerSecond": 50,
    "maxConnectsPerDestPerSecond": 8,
    "maxConnectsPerDestPerMinute": 60,
    "maxInFlightSyns": 256,
    "maxConcurrentStreamsPerConnection": 256,
    "maxConcurrentConnections": 1024,
    "synFloodSignature": {
      "enabled": true,
      "windowMs": 2000,
      "minSamples": 32,
      "failedHandshakeRatio": 0.75
    },
    "wsCloseAfterViolations": 16,
    "logBlockedDials": true
  },

  "reputation": {
    "enabled": true,
    "storePath": "./data/mrrowisp-reputation.json",
    "saveIntervalSeconds": 30,
    "scoreDecayPerHour": 1,
    "evictAfterDays": 7,
    "thresholds": { "warn": 21, "throttle": 51, "strict": 81 },
    "weights": {
      "privateEgress": 15,
      "synSignature": 25,
      "twispNoAuth": 40,
      "burstRate": 5,
      "successfulStream": -2,
      "requestKnownBadDest": 2
    },
    "destinationWeights": {
      "privateEgress": 20,
      "synSignature": 30,
      "distinctSourcesEscalation": 1
    }
  },

  "egress": {
    "allowPrivate": false,
    "allowIPs": [],
    "allowCIDRs": [],
    "denyIPs": [],
    "denyCIDRs": []
  }
}
```

### Structured log lines

All enforcement actions emit a single-line JSON record to stderr via `log.Printf`:

```json
{"ts":"2026-05-19T13:09:58Z","event":"flood_block","reason":"per_dest_rate","srcIP":"1.2.3.4","dstIP":"153.75.225.178","dstPort":81,"streamId":42}
{"ts":"2026-05-19T13:09:58Z","event":"egress_block","reason":"private","srcIP":"1.2.3.4","dstIP":"10.0.0.5","dstPort":22}
{"ts":"2026-05-19T13:09:58Z","event":"syn_signature","srcIP":"1.2.3.4","dstIP":"153.75.225.178","dstPort":81,"samples":34,"failedRatio":0.91}
{"ts":"2026-05-19T13:09:58Z","event":"reputation_update","kind":"source","key":"1.2.3.4","delta":25,"reason":"synSignature","newScore":62}
```

This is fail2ban-friendly: a single regex like `event":"flood_block".*srcIP":"([^"]+)"` will pick out IPs to ban at the OS level.

## Backwards compatibility

- **All new behavior is on-by-default**; defaults are chosen so a legitimate proxy at modest load is unaffected (50 CONNECTs/sec/source is generous for a browser-tab opening dozens of subresources; 8/sec to the same `dstIP:dstPort` covers WebSocket bursts and HTTP/1.1 connection reuse).
- **Behavior change:** `egress.allowPrivate: false` blocks SSRF by default. Documented prominently. Homelab/k8s users flip `allowPrivate: true` or specify `allowCIDRs`.
- **Config field migration:** Go accepts BOTH `dnsServer` (singular, legacy) and `dnsServers` (plural, current); deprecation warning when the legacy key is used.
- **No fields removed.** `maxConnectsPerSecond` (top-level, per-WS) stays for compatibility; new fields are in nested blocks.

## Testing

- **Unit tests** for each new file (sliding window, egress evaluator, reputation arithmetic + persistence round-trip, SYN signature, client-IP extraction).
- **Integration test** (`integration_test.go`, behind `-tags integration`): boots the server, opens a real WS, drives the SYN-flood pattern (50 CONNECTs to `127.0.0.1:1` in 100ms), asserts:
  - At least one stream closes with `closeReasonBlocked` due to egress (127.0.0.1 = loopback).
  - Set `egress.allowPrivate: true` and re-run; this time at least one stream closes with `closeReasonThrottled` due to per-dest rate.
  - Reputation store contains an entry for the source with non-zero score and `synSignature` event.
- **Race detector** (`go test -race`) runs in CI.

## Rollout

Single PR with the following commit sequence (each commit independently passing tests):

1. `wisp: add safe maskXOR, cap payload length, error on permessage-deflate`
2. `wisp: replace close(writeCh) race with sync.Once + done channel`
3. `wisp: add ResolveClientIP and trustedProxies config`
4. `wisp: add egress policy with private-range default-deny`
5. `wisp: add limits package (in-flight SYNs, per-source/per-dest sliding windows, concurrency caps)`
6. `wisp: add reputation store with JSON persistence`
7. `wisp: add SYN-flood signature detector`
8. `wisp: wire enforcement pipeline into handleConnectPacket`
9. `wisp/v2: constant-time password compare, optional bcrypt`
10. `wisp/twisp: require auth, log attempts to reputation`
11. `main: add config sub-structs, file-only -config flag, HTTP server timeouts`
12. `ts: temp-file config, fix dnsServer schema, add new builder methods, reuse WebSocketServer in route()`
13. `docs: README + example.config.json updates`

## Risks

- **False positives at the warn/throttle tier:** a power user behind CGNAT could hit per-source rate. Mitigation: `successfulStream: -2` decay; `scoreDecayPerHour: 1` natural recovery; thresholds are user-tunable.
- **Reputation file corruption:** atomic rename + tmp file means partial writes are impossible. On load failure, log warning and start with empty store.
- **Memory growth in reputation store under attack:** eviction goroutine + score-decay bounds it. Worst case: 7 days × estimated burn rate. Adding a hard `maxEntries` cap (LRU eviction) is future work; documented in code as TODO.
- **Behavior change for existing users on private networks:** `egress.allowPrivate: false` default. README has a prominent migration note.
- **`permessage-deflate` users:** any deployment with this enabled will fail to start with a config validation error. Documented.

## Appendix A — Security findings inventory

Findings from the initial review, with the commit number that addresses each:

| # | Finding | Severity | Commit |
|---|---|---|---|
| 1 | Unauthenticated open proxy / SSRF (no IP-egress filter) | Critical | 4 |
| 2 | TCP SYN-flood / amplification vector | Critical | 5, 6, 7, 8 |
| 3 | Twisp = unauthenticated RCE | Critical | 10 |
| 4 | Plaintext password compare, timing oracle | High | 9 |
| 5 | `recover()` swallowing panics in writeLoop | High | 2 |
| 6 | Unbounded payload allocation in wsreader | High | 1 |
| 7 | Shared PayloadBuffer fragility | Medium | doc-only (1) |
| 8 | `unsafe.Pointer` in maskXOR (alignment) | Medium | 1 |
| 9 | `close(writeCh)` race | High | 2 |
| 10 | DNSCache uses only `servers[0]`, no rotation | Medium | 4 (via egress recheck) |
| 11 | Negative DNS cached as long as positive | Medium | future (out of scope) |
| 12 | splitShell w/ os.Environ() | Medium | 10 (auth-gates the path) |
| 13 | No HTTP timeouts | High | 11 |
| 14 | No global goroutine / connection cap | High | 5 |
| 15 | `route()` leaks WebSocketServer per upgrade | Medium | 12 |
| 16 | TS spawn passes secrets on argv | High | 12 |
| 17 | Go -config string passes secrets on argv | High | 11 |
| 18 | permessage-deflate inconsistency with hand-rolled reader | Medium | 1 |
| 19 | `dnsServer` vs `dnsServers` field mismatch | Low | 11, 12 |
| 20 | MaxConnectsPerSecond not exposed in TS/example | Low | 13 |
| 21 | Unused close-reason constants | Hygiene | not addressed |
| 22 | .dockerignore review | Hygiene | 13 |

## Appendix B — OVH abuse evidence

Two abuse tickets reviewed via Gmail on 2026-05-19:

- **Ticket 678956**, source IP `15.204.247.101`. 22 Kpps / 11 Mbps SYN flood to `153.75.225.178:81` on 2026-05-06.
- **Ticket 680426**, source IP `15.204.116.230`. 31 Kpps / 15 Mbps SYN flood to `153.75.225.178:81` on 2026-05-10. Edge firewall did not stop attempts.

Both have the exact signature of the abuse this design targets: SYN-only outbound, single destination IP:port, hundreds of unique source ports per second from the Wisp host.
