# mrrowisp Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the SYN-flood / SSRF abuse vector in mrrowisp by adding a per-destination rate limiter, an SSRF egress policy, a SYN-flood signature detector, and a persistent reputation store; fix all critical/high security findings from the review.

**Architecture:** New Go files under `wisp/` for limits, egress policy, reputation, signature detection, and client-IP resolution. Modified `handleConnectPacket` runs an enforcement pipeline that consults all of them. Reputation persists to a JSON file via atomic rename. Existing hand-rolled WS reader gets payload-length cap + safe maskXOR. TS wrapper switches argv-config for tempfile-config.

**Tech Stack:** Go 1.21+ (project uses 1.24), `crypto/subtle`, `golang.org/x/crypto/bcrypt`, `net`, `encoding/json`. TS: `ws`, `child_process`, existing build.

**Source spec:** `docs/superpowers/specs/2026-05-19-mrrowisp-hardening-design.md`

---

## File map

### New Go files
- `wisp/clientip.go` — `ResolveClientIP(r, trustedProxies, headers)` extracts client IP with safe header trust.
- `wisp/clientip_test.go` — covers RemoteAddr, trusted-proxy header, untrusted-proxy header.
- `wisp/egress.go` — `EgressPolicy` with `Evaluate(ip)` returning (allowed, reason).
- `wisp/egress_test.go` — IPv4/IPv6 private/loopback/multicast/CIDR allow/deny.
- `wisp/limits.go` — sliding-window rate limiters keyed by string; counting semaphore for in-flight SYNs; concurrency counters.
- `wisp/limits_test.go` — concurrent rate-limit correctness; semaphore acquire/release; window rollover.
- `wisp/reputation.go` — in-memory reputation store with JSON persistence (atomic rename), score decay, eviction.
- `wisp/reputation_test.go` — score arithmetic, decay, persistence round-trip, distinct-source escalation.
- `wisp/signature.go` — per-(WS, dst) ring buffer of dial outcomes; match condition.
- `wisp/signature_test.go` — match/no-match boundary cases.
- `wisp/wsreader_test.go` — payload-cap, safe vs reference maskXOR equivalence.
- `wisp/v2_test.go` — constant-time password compare; bcrypt verification.

### Modified Go files
- `wisp/wisp.go` — `Config` gains `FloodProtection`, `Reputation`, `Egress`, `TrustedProxies`, `TrustedHeaders`, `MaxPayloadBytes` fields; `CreateWispHandler` constructs limiter, store, http.Server with timeouts.
- `wisp/wisp-connection.go` — `wispConnection` carries `srcIP`, `globals *globalState`; `handleConnectPacket` runs the enforcement pipeline; `close(writeCh)` race fixed with `sync.Once` + done channel.
- `wisp/wisp-stream.go` — egress check after DNS, in-flight SYN semaphore around Dial, signature observe-outcome.
- `wisp/wsreader.go` — payload-length cap; safe `maskXOR`; reject permessage-deflate.
- `wisp/v2.go` — `subtle.ConstantTimeCompare` for password; bcrypt support; deprecation log.
- `wisp/twisp.go` — refuse `streamTypeTerm` unless authenticated when `enableTwisp` is on; log attempts.
- `main.go` — config sub-structs; reject JSON-string `-config`; `http.Server` with timeouts.

### Modified TS files
- `src/types.d.ts` — add new config types.
- `src/server/index.ts` — temp-file config; reuse one `WebSocketServer` in `route()`; add new builder methods.
- `example.config.json` — show new blocks.
- `README.md` — config table updated.

---

## Task 1: Cap payload length, safe maskXOR, reject permessage-deflate

**Files:**
- Modify: `wisp/wisp.go` (add `MaxPayloadBytes` to Config; default 1 MiB; reject permessage-deflate)
- Modify: `wisp/wsreader.go` (cap; replace unsafe maskXOR)
- Test: `wisp/wsreader_test.go` (new)

- [ ] **Step 1.1: Write the failing tests**

Create `wisp/wsreader_test.go`:

```go
package wisp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// referenceMaskXOR is the byte-by-byte reference implementation.
func referenceMaskXOR(b []byte, key [4]byte) {
	for i := range b {
		b[i] ^= key[i&3]
	}
}

func TestMaskXOREquivalence(t *testing.T) {
	key := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}
	for size := 0; size <= 1024; size++ {
		a := make([]byte, size)
		b := make([]byte, size)
		for i := range a {
			a[i] = byte(i)
			b[i] = byte(i)
		}
		maskXOR(a, key)
		referenceMaskXOR(b, key)
		if !bytes.Equal(a, b) {
			t.Fatalf("mismatch at size %d", size)
		}
	}
}

func TestMaskXORUnaligned(t *testing.T) {
	// unaligned pointer: slice into a backing array starting at offset 1
	backing := make([]byte, 200)
	for i := range backing {
		backing[i] = byte(i)
	}
	a := backing[1:129]
	b := append([]byte(nil), a...)
	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	maskXOR(a, key)
	referenceMaskXOR(b, key)
	if !bytes.Equal(a, b) {
		t.Fatal("unaligned mismatch")
	}
}

func TestPayloadLengthCapped(t *testing.T) {
	// Build a single client WS frame with payloadLen = 2 MiB; the reader must
	// not allocate it. We invoke the reader by feeding bytes through a pipe.
	cfg := DefaultConfig()
	cfg.MaxPayloadBytes = 1024 // tiny cap for the test
	cfg.InitResolver()

	// Frame: FIN=1, opcode=2, masked=1, len=127, ext64 = 2*1024 (2x cap)
	header := []byte{0x82, 0x80 | 127, 0, 0, 0, 0, 0, 0, 0x08, 0x00}
	mask := []byte{1, 2, 3, 4}
	// Server should bail out reading before allocating; we just need the
	// header parser to refuse and close.

	pr, pw := newPipeConn()
	defer pr.Close()
	defer pw.Close()

	wc := &wispConnection{netConn: pr, writeCh: make(chan writeReq, 4), config: cfg, twispStreams: newTwisp()}
	wc.handshakeDone = nil

	done := make(chan struct{})
	go func() {
		wc.readLoop()
		close(done)
	}()

	pw.Write(header)
	pw.Write(mask)
	// don't write the payload: readLoop should have already closed.

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not abort on oversized frame")
	}

	_ = binary.BigEndian
}
```

The last test refers to `newPipeConn` — add this helper at the bottom:

```go
import (
	"net"
	"time"
)

// newPipeConn returns a pair of in-memory net.Conn endpoints.
func newPipeConn() (net.Conn, net.Conn) {
	return net.Pipe()
}
```

- [ ] **Step 1.2: Run tests, expect FAIL**

Run: `go test ./wisp -run 'TestMaskXOR|TestPayloadLength' -v`

Expected: compile errors (referencing `MaxPayloadBytes`, the cap behavior); after fixing imports, the cap test fails because the existing reader allocates without checking.

- [ ] **Step 1.3: Add `MaxPayloadBytes` to Config**

Edit `wisp/wisp.go`. Add field:

```go
type Config struct {
	// ... existing fields ...
	MaxPayloadBytes int
}
```

In `DefaultConfig()`:

```go
return &Config{
	// ... existing ...
	MaxPayloadBytes: 1 << 20, // 1 MiB
}
```

In `CreateWispHandler`, before constructing the upgrader, validate:

```go
if config.MaxPayloadBytes <= 0 {
	config.MaxPayloadBytes = 1 << 20
}
if config.WebsocketPermessageDeflate {
	panic("websocketPermessageDeflate is not supported by the hand-rolled reader; set it to false")
}
```

- [ ] **Step 1.4: Cap payloadLen and use safe maskXOR**

Edit `wisp/wsreader.go`. Replace the existing `maskXOR` body with a safe word-loop:

```go
func maskXOR(b []byte, key [4]byte) {
	maskKey := binary.LittleEndian.Uint32(key[:])
	key64 := uint64(maskKey)<<32 | uint64(maskKey)
	// 8-byte chunks
	i := 0
	for ; i+8 <= len(b); i += 8 {
		v := binary.LittleEndian.Uint64(b[i:])
		v ^= key64
		binary.LittleEndian.PutUint64(b[i:], v)
	}
	// tail
	for j := i; j < len(b); j++ {
		b[j] ^= key[j&3]
	}
}
```

Remove the `unsafe` import.

In `readLoop`, after determining `payloadLen`, add the cap check before allocating:

```go
maxPayload := uint64(c.config.MaxPayloadBytes)
if maxPayload > 0 && payloadLen > maxPayload {
	return
}
```

- [ ] **Step 1.5: Run tests, expect PASS**

Run: `go test ./wisp -run 'TestMaskXOR|TestPayloadLength' -v -race`

Expected: all PASS.

- [ ] **Step 1.6: Commit**

```bash
git add wisp/wsreader.go wisp/wsreader_test.go wisp/wisp.go
git commit -m "wisp: cap WS payload length, replace unsafe maskXOR with safe variant"
```


---

## Task 2: Fix `close(writeCh)` race with sync.Once + done channel

**Files:**
- Modify: `wisp/wisp-connection.go` (writeCh lifecycle)
- Test: `wisp/wisp_connection_test.go` (new)

- [ ] **Step 2.1: Write the failing test**

Create `wisp/wisp_connection_test.go`:

```go
package wisp

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestQueueWriteAfterCloseNoPanic(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	wc := &wispConnection{
		netConn:      a,
		writeCh:      make(chan writeReq, 8),
		config:       DefaultConfig(),
		twispStreams: newTwisp(),
	}
	wc.initWriteLifecycle()
	go wc.writeLoop()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				wc.queueWrite([]byte{0x82, 0})
			}
		}()
	}

	time.Sleep(10 * time.Millisecond)
	wc.deleteAllWispStreams() // closes writeCh

	wg.Wait() // must not panic
}
```

- [ ] **Step 2.2: Run, expect FAIL/PANIC**

Run: `go test ./wisp -run TestQueueWriteAfterClose -v -race`
Expected: panic on send to closed channel.

- [ ] **Step 2.3: Add done channel and Once**

Edit `wisp/wisp-connection.go`. Add fields:

```go
type wispConnection struct {
	// ... existing fields ...
	writeDone chan struct{}
	writeOnce sync.Once
}
```

Add an initializer (called from CreateWispHandler):

```go
func (c *wispConnection) initWriteLifecycle() {
	c.writeDone = make(chan struct{})
}
```

Replace `queueWrite`:

```go
func (c *wispConnection) queueWrite(data []byte) {
	if c.isClosed.Load() {
		return
	}
	select {
	case <-c.writeDone:
		return
	case c.writeCh <- writeReq{data: data}:
	default:
		// channel full; drop and close to avoid blocking the reader
		c.close()
	}
}
```

Replace `deleteAllWispStreams`'s channel-close section:

```go
func (c *wispConnection) deleteAllWispStreams() {
	c.isClosed.Store(true)
	c.streams.Range(func(key, value any) bool {
		stream := value.(*wispStream)
		stream.close(closeReasonUnspecified)
		return true
	})
	if c.twispStreams != nil {
		c.twispStreams.mu.RLock()
		for _, ts := range c.twispStreams.streams {
			ts.close(closeReasonUnspecified)
		}
		c.twispStreams.mu.RUnlock()
	}
	c.writeOnce.Do(func() {
		close(c.writeDone)
		close(c.writeCh)
	})
}
```

Update `writeLoop` to exit when `writeDone` fires AND drain channel:

```go
func (c *wispConnection) writeLoop() {
	for {
		select {
		case req, ok := <-c.writeCh:
			if !ok {
				return
			}
			bufs := net.Buffers{req.data}
			n := len(c.writeCh)
			for i := 0; i < n; i++ {
				r, ok := <-c.writeCh
				if !ok {
					break
				}
				bufs = append(bufs, r.data)
			}
			if _, err := bufs.WriteTo(c.netConn); err != nil {
				c.isClosed.Store(true)
				c.netConn.Close()
				return
			}
		case <-c.writeDone:
			return
		}
	}
}
```

Remove `defer func() { recover() }()` from `queueWrite` and `deleteAllWispStreams`.

In `CreateWispHandler` where `wc` is constructed, add `wc.initWriteLifecycle()` before `go wc.writeLoop()`.

- [ ] **Step 2.4: Run, expect PASS**

Run: `go test ./wisp -run TestQueueWriteAfterClose -v -race -count=5`

Expected: PASS, no panics across 5 runs.

- [ ] **Step 2.5: Commit**

```bash
git add wisp/wisp-connection.go wisp/wisp.go wisp/wisp_connection_test.go
git commit -m "wisp: fix close(writeCh) race with sync.Once + done channel"
```


---

## Task 3: Add `ResolveClientIP` and trustedProxies config

**Files:**
- Create: `wisp/clientip.go`
- Create: `wisp/clientip_test.go`
- Modify: `wisp/wisp.go` (config fields)

- [ ] **Step 3.1: Write the failing tests**

Create `wisp/clientip_test.go`:

```go
package wisp

import (
	"net"
	"net/http"
	"testing"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestResolveClientIPFromRemoteAddr(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:12345"
	ip := ResolveClientIP(r, nil, nil)
	if ip.String() != "203.0.113.5" {
		t.Fatalf("got %v", ip)
	}
}

func TestResolveClientIPIgnoresUntrustedHeader(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:1"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	ip := ResolveClientIP(r, nil, []string{"X-Forwarded-For"})
	if ip.String() != "203.0.113.5" {
		t.Fatalf("got %v", ip)
	}
}

func TestResolveClientIPTrustsHeaderFromTrustedProxy(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1"
	r.Header.Set("CF-Connecting-IP", "198.51.100.7")
	trusted := []*net.IPNet{mustCIDR("10.0.0.0/8")}
	ip := ResolveClientIP(r, trusted, []string{"CF-Connecting-IP"})
	if ip.String() != "198.51.100.7" {
		t.Fatalf("got %v", ip)
	}
}

func TestResolveClientIPXFFRightmostInTrust(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1"
	// XFF: rightmost is the most-recent (trusted) proxy hop. The previous hop
	// is what we want.
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	trusted := []*net.IPNet{mustCIDR("10.0.0.0/8")}
	ip := ResolveClientIP(r, trusted, []string{"X-Forwarded-For"})
	if ip.String() != "5.6.7.8" {
		t.Fatalf("got %v", ip)
	}
}

func TestResolveClientIPFallbackOnGarbage(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "garbage"
	ip := ResolveClientIP(r, nil, nil)
	if !ip.IsUnspecified() {
		t.Fatalf("got %v", ip)
	}
}
```

- [ ] **Step 3.2: Run, expect FAIL**

Run: `go test ./wisp -run TestResolveClientIP -v`
Expected: undefined: ResolveClientIP.

- [ ] **Step 3.3: Implement clientip.go**

Create `wisp/clientip.go`:

```go
package wisp

import (
	"net"
	"net/http"
	"strings"
)

// ResolveClientIP returns the client IP for r. If the immediate peer
// (r.RemoteAddr) is in trustedProxies, headers are consulted in order and
// the first usable IP is returned. Otherwise the peer IP is returned.
// Always returns a non-nil IP; falls back to IPv4 unspecified on error.
func ResolveClientIP(r *http.Request, trustedProxies []*net.IPNet, headers []string) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return net.IPv4zero
	}

	if !ipInAny(peer, trustedProxies) {
		return peer
	}

	for _, h := range headers {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		// X-Forwarded-For semantics: comma-separated, leftmost = original
		// client. Walk right-to-left, skipping any IP that is itself in
		// trustedProxies; first non-trusted IP is the answer.
		parts := strings.Split(v, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := net.ParseIP(strings.TrimSpace(parts[i]))
			if candidate == nil {
				continue
			}
			if ipInAny(candidate, trustedProxies) {
				continue
			}
			return candidate
		}
	}
	return peer
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3.4: Add config fields**

Edit `wisp/wisp.go`. Add to `Config`:

```go
TrustedProxies []*net.IPNet
TrustedHeaders []string
```

These will be populated from the JSON `trustedProxies []string` and `trustedHeaders []string` by the parser in `main.go` later (Task 11). For now leave them as-is.

- [ ] **Step 3.5: Run, expect PASS**

Run: `go test ./wisp -run TestResolveClientIP -v`
Expected: all PASS.

- [ ] **Step 3.6: Commit**

```bash
git add wisp/clientip.go wisp/clientip_test.go wisp/wisp.go
git commit -m "wisp: add ResolveClientIP with trusted-proxy header support"
```


---

## Task 4: Egress policy with private-range default-deny

**Files:**
- Create: `wisp/egress.go`
- Create: `wisp/egress_test.go`
- Modify: `wisp/wisp.go` (config fields)

- [ ] **Step 4.1: Write the failing tests**

Create `wisp/egress_test.go`:

```go
package wisp

import (
	"net"
	"testing"
)

func mustNet(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestEgressDeniesPrivateByDefault(t *testing.T) {
	p := &EgressPolicy{}
	cases := []string{"10.0.0.1", "192.168.1.5", "172.16.5.5", "127.0.0.1", "169.254.1.1", "::1", "fc00::1", "fe80::1", "0.0.0.0", "224.0.0.1"}
	for _, c := range cases {
		ok, _ := p.Evaluate(net.ParseIP(c))
		if ok {
			t.Errorf("expected %s to be denied", c)
		}
	}
}

func TestEgressAllowsPublic(t *testing.T) {
	p := &EgressPolicy{}
	cases := []string{"1.1.1.1", "8.8.8.8", "153.75.225.178", "2001:4860:4860::8888"}
	for _, c := range cases {
		ok, reason := p.Evaluate(net.ParseIP(c))
		if !ok {
			t.Errorf("expected %s to be allowed, got reason %q", c, reason)
		}
	}
}

func TestEgressAllowPrivate(t *testing.T) {
	p := &EgressPolicy{AllowPrivate: true}
	ok, _ := p.Evaluate(net.ParseIP("10.0.0.5"))
	if !ok {
		t.Fatal("expected allowPrivate to permit 10.0.0.5")
	}
}

func TestEgressDenyOverridesAllow(t *testing.T) {
	p := &EgressPolicy{
		AllowPrivate: true,
		DenyIPs:      map[string]struct{}{"10.0.0.5": {}},
	}
	ok, reason := p.Evaluate(net.ParseIP("10.0.0.5"))
	if ok || reason != "deny_ip" {
		t.Fatalf("got ok=%v reason=%q", ok, reason)
	}
}

func TestEgressAllowCIDROverridesPrivate(t *testing.T) {
	p := &EgressPolicy{
		AllowCIDRs: []*net.IPNet{mustNet("192.168.0.0/16")},
	}
	ok, _ := p.Evaluate(net.ParseIP("192.168.5.5"))
	if !ok {
		t.Fatal("expected explicit allow to override private")
	}
}

func TestEgressDenyCIDR(t *testing.T) {
	p := &EgressPolicy{
		DenyCIDRs: []*net.IPNet{mustNet("153.75.225.0/24")},
	}
	ok, reason := p.Evaluate(net.ParseIP("153.75.225.178"))
	if ok || reason != "deny_cidr" {
		t.Fatalf("got ok=%v reason=%q", ok, reason)
	}
}

func TestEgressIPv4MappedV6Unwrap(t *testing.T) {
	p := &EgressPolicy{}
	ok, reason := p.Evaluate(net.ParseIP("::ffff:127.0.0.1"))
	if ok || reason != "loopback" {
		t.Fatalf("got ok=%v reason=%q", ok, reason)
	}
}
```

- [ ] **Step 4.2: Run, expect FAIL**

Run: `go test ./wisp -run TestEgress -v`
Expected: undefined: EgressPolicy.

- [ ] **Step 4.3: Implement `wisp/egress.go`**

```go
package wisp

import "net"

// EgressPolicy decides whether outbound connections to a given IP are
// permitted. Order: deny, allow, kind-based deny.
type EgressPolicy struct {
	AllowPrivate bool
	AllowIPs     map[string]struct{}
	AllowCIDRs   []*net.IPNet
	DenyIPs      map[string]struct{}
	DenyCIDRs    []*net.IPNet
}

func (p *EgressPolicy) Evaluate(ip net.IP) (bool, string) {
	if ip == nil {
		return false, "invalid"
	}
	// Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) so v4 rules apply.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if p.DenyIPs != nil {
		if _, ok := p.DenyIPs[ip.String()]; ok {
			return false, "deny_ip"
		}
	}
	for _, n := range p.DenyCIDRs {
		if n.Contains(ip) {
			return false, "deny_cidr"
		}
	}

	explicitAllow := false
	if p.AllowIPs != nil {
		if _, ok := p.AllowIPs[ip.String()]; ok {
			explicitAllow = true
		}
	}
	if !explicitAllow {
		for _, n := range p.AllowCIDRs {
			if n.Contains(ip) {
				explicitAllow = true
				break
			}
		}
	}
	if explicitAllow {
		return true, ""
	}

	if ip.IsUnspecified() {
		return false, "unspecified"
	}
	if ip.IsLoopback() {
		if p.AllowPrivate {
			return true, ""
		}
		return false, "loopback"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		if p.AllowPrivate {
			return true, ""
		}
		return false, "link_local"
	}
	if ip.IsPrivate() {
		if p.AllowPrivate {
			return true, ""
		}
		return false, "private"
	}
	if ip.IsMulticast() {
		return false, "multicast"
	}
	return true, ""
}
```

- [ ] **Step 4.4: Add config fields**

Edit `wisp/wisp.go`:

```go
type Config struct {
	// ... existing ...
	Egress *EgressPolicy
}
```

- [ ] **Step 4.5: Run, expect PASS**

Run: `go test ./wisp -run TestEgress -v`

- [ ] **Step 4.6: Commit**

```bash
git add wisp/egress.go wisp/egress_test.go wisp/wisp.go
git commit -m "wisp: add egress policy with private-range default-deny"
```


---

## Task 5: Limits package (sliding windows + in-flight SYN semaphore)

**Files:**
- Create: `wisp/limits.go`
- Create: `wisp/limits_test.go`
- Modify: `wisp/wisp.go` (config + global state)

- [ ] **Step 5.1: Write failing tests**

Create `wisp/limits_test.go`:

```go
package wisp

import (
	"sync"
	"testing"
	"time"
)

func TestSlidingWindowAllow(t *testing.T) {
	w := NewSlidingWindow(3, time.Second)
	for i := 0; i < 3; i++ {
		if !w.Allow("k") {
			t.Fatalf("attempt %d denied early", i)
		}
	}
	if w.Allow("k") {
		t.Fatal("4th attempt should be denied")
	}
	// Different key is independent
	if !w.Allow("k2") {
		t.Fatal("key2 should be allowed")
	}
}

func TestSlidingWindowRollover(t *testing.T) {
	w := NewSlidingWindow(2, 50*time.Millisecond)
	w.Allow("k")
	w.Allow("k")
	if w.Allow("k") {
		t.Fatal("should be denied")
	}
	time.Sleep(80 * time.Millisecond)
	if !w.Allow("k") {
		t.Fatal("should allow after rollover")
	}
}

func TestSlidingWindowConcurrent(t *testing.T) {
	w := NewSlidingWindow(100, time.Second)
	var wg sync.WaitGroup
	var allowed int64
	var mu sync.Mutex
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if w.Allow("k") {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if allowed != 100 {
		t.Fatalf("expected exactly 100 allowed, got %d", allowed)
	}
}

func TestSemaphoreAcquireRelease(t *testing.T) {
	s := NewSemaphore(2)
	if !s.TryAcquire() {
		t.Fatal("acquire 1")
	}
	if !s.TryAcquire() {
		t.Fatal("acquire 2")
	}
	if s.TryAcquire() {
		t.Fatal("acquire 3 should fail")
	}
	s.Release()
	if !s.TryAcquire() {
		t.Fatal("acquire after release")
	}
}
```

- [ ] **Step 5.2: Run, expect FAIL**

Run: `go test ./wisp -run 'TestSliding|TestSemaphore' -v`
Expected: undefined identifiers.

- [ ] **Step 5.3: Implement `wisp/limits.go`**

```go
package wisp

import (
	"sync"
	"sync/atomic"
	"time"
)

// SlidingWindow is a keyed fixed-window rate limiter. Each key has its own
// window that resets after `window` duration; up to `limit` Allow() calls
// per window return true.
type SlidingWindow struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	entries map[string]*windowEntry
}

type windowEntry struct {
	start time.Time
	count int
}

func NewSlidingWindow(limit int, window time.Duration) *SlidingWindow {
	return &SlidingWindow{
		limit:   limit,
		window:  window,
		entries: make(map[string]*windowEntry),
	}
}

func (w *SlidingWindow) Allow(key string) bool {
	if w == nil || w.limit <= 0 {
		return true
	}
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	e, ok := w.entries[key]
	if !ok || now.Sub(e.start) >= w.window {
		w.entries[key] = &windowEntry{start: now, count: 1}
		return true
	}
	e.count++
	return e.count <= w.limit
}

// Evict deletes entries whose window has expired more than `idle` ago. Call
// periodically from a maintenance goroutine.
func (w *SlidingWindow) Evict(idle time.Duration) {
	if w == nil {
		return
	}
	cutoff := time.Now().Add(-idle)
	w.mu.Lock()
	for k, e := range w.entries {
		if e.start.Before(cutoff) {
			delete(w.entries, k)
		}
	}
	w.mu.Unlock()
}

// Semaphore is a counting semaphore. TryAcquire is non-blocking.
type Semaphore struct {
	max     int64
	current int64
}

func NewSemaphore(max int) *Semaphore {
	return &Semaphore{max: int64(max)}
}

func (s *Semaphore) TryAcquire() bool {
	if s == nil || s.max <= 0 {
		return true
	}
	for {
		cur := atomic.LoadInt64(&s.current)
		if cur >= s.max {
			return false
		}
		if atomic.CompareAndSwapInt64(&s.current, cur, cur+1) {
			return true
		}
	}
}

func (s *Semaphore) Release() {
	if s == nil || s.max <= 0 {
		return
	}
	atomic.AddInt64(&s.current, -1)
}

// Globals holds process-wide enforcement state injected into wispConnection.
type Globals struct {
	PerSource      *SlidingWindow
	PerDestSec     *SlidingWindow
	PerDestMin     *SlidingWindow
	InFlightSyns   *Semaphore
	Connections    *Semaphore
	Egress         *EgressPolicy
	Reputation     *Reputation // set in Task 6
	Signature      *Signatures // set in Task 7
}
```

(The `Reputation` and `Signatures` types are introduced in later tasks; leave the field references as bare pointers — Go zero-values are fine until those tasks land. Add the types before referencing them to keep compilation green.)

For this task, also add stub types so the package compiles. Add to `wisp/limits.go`:

```go
// Reputation and Signatures are introduced in Task 6 / Task 7. To keep this
// file self-contained for now, declare them as opaque pointers.
type Reputation struct{}
type Signatures struct{}
```

These will be **replaced** (not extended) in tasks 6 and 7. The replacement file removes the stubs.

- [ ] **Step 5.4: Run, expect PASS**

Run: `go test ./wisp -run 'TestSliding|TestSemaphore' -v -race`

- [ ] **Step 5.5: Commit**

```bash
git add wisp/limits.go wisp/limits_test.go wisp/wisp.go
git commit -m "wisp: add sliding-window limiter and counting semaphore"
```


---

## Task 6: Reputation store with JSON persistence

**Files:**
- Create: `wisp/reputation.go` (replacing the `Reputation` stub from Task 5)
- Create: `wisp/reputation_test.go`

- [ ] **Step 6.1: Write failing tests**

Create `wisp/reputation_test.go`:

```go
package wisp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReputationAddAndScore(t *testing.T) {
	r := NewReputation(ReputationConfig{Weights: map[string]int{"foo": 10}})
	r.AddSource("1.1.1.1", "foo")
	if r.SourceScore("1.1.1.1") != 10 {
		t.Fatalf("got %d", r.SourceScore("1.1.1.1"))
	}
	r.AddSource("1.1.1.1", "foo")
	if r.SourceScore("1.1.1.1") != 20 {
		t.Fatalf("got %d", r.SourceScore("1.1.1.1"))
	}
}

func TestReputationClamps(t *testing.T) {
	r := NewReputation(ReputationConfig{Weights: map[string]int{"big": 60}})
	r.AddSource("a", "big")
	r.AddSource("a", "big")
	if r.SourceScore("a") != 100 {
		t.Fatalf("expected clamp to 100, got %d", r.SourceScore("a"))
	}
	r2 := NewReputation(ReputationConfig{Weights: map[string]int{"neg": -200}})
	r2.AddSource("b", "neg")
	if r2.SourceScore("b") != 0 {
		t.Fatalf("expected clamp to 0, got %d", r2.SourceScore("b"))
	}
}

func TestReputationDestDistinctSources(t *testing.T) {
	r := NewReputation(ReputationConfig{
		DestWeights: map[string]int{"hit": 5, "distinctSourcesEscalation": 1},
	})
	for i := 0; i < 50; i++ {
		r.AddDest("9.9.9.9", 80, "hit", net.ParseIP(fmt.Sprintf("10.0.0.%d", i)))
	}
	if got := r.DestScore("9.9.9.9", 80); got < 50 {
		t.Fatalf("got %d", got)
	}
}

func TestReputationPersistRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rep.json")
	r := NewReputation(ReputationConfig{
		Weights: map[string]int{"x": 7}, StorePath: path,
	})
	r.AddSource("1.2.3.4", "x")
	if err := r.SaveNow(); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() == 0 {
		t.Fatal("empty file")
	}
	r2 := NewReputation(ReputationConfig{
		Weights: map[string]int{"x": 7}, StorePath: path,
	})
	if err := r2.Load(); err != nil {
		t.Fatal(err)
	}
	if r2.SourceScore("1.2.3.4") != 7 {
		t.Fatalf("got %d", r2.SourceScore("1.2.3.4"))
	}
}

func TestReputationDecay(t *testing.T) {
	r := NewReputation(ReputationConfig{
		Weights: map[string]int{"x": 50}, DecayPerHour: 50,
	})
	r.AddSource("a", "x")
	// Simulate 1h elapsed.
	r.ForceDecay(time.Hour)
	if got := r.SourceScore("a"); got != 0 {
		t.Fatalf("expected 0 after decay, got %d", got)
	}
}
```

Add the imports `"fmt"` and `"net"` at the top of the test file.

- [ ] **Step 6.2: Run, expect FAIL**

Run: `go test ./wisp -run TestReputation -v`
Expected: undefined types.

- [ ] **Step 6.3: Replace the stub with `wisp/reputation.go`**

Delete the `type Reputation struct{}` line from `wisp/limits.go` (it was a stub).

Create `wisp/reputation.go`:

```go
package wisp

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ReputationConfig struct {
	Enabled      bool
	StorePath    string
	DecayPerHour int
	EvictAfter   time.Duration
	Weights      map[string]int
	DestWeights  map[string]int
	Thresholds   struct {
		Warn     int
		Throttle int
		Strict   int
	}
}

type SourceEntry struct {
	Score     int            `json:"score"`
	FirstSeen time.Time      `json:"firstSeen"`
	LastSeen  time.Time      `json:"lastSeen"`
	Events    map[string]int `json:"events"`
}

type DestEntry struct {
	Score           int             `json:"score"`
	FirstSeen       time.Time       `json:"firstSeen"`
	LastSeen        time.Time       `json:"lastSeen"`
	Events          map[string]int  `json:"events"`
	DistinctSources int             `json:"distinctSources"`
	SeenSources     map[string]bool `json:"seenSources"`
}

type Reputation struct {
	cfg       ReputationConfig
	mu        sync.RWMutex
	sources   map[string]*SourceEntry
	dests     map[string]*DestEntry
	lastDecay time.Time
}

func NewReputation(cfg ReputationConfig) *Reputation {
	return &Reputation{
		cfg:       cfg,
		sources:   make(map[string]*SourceEntry),
		dests:     make(map[string]*DestEntry),
		lastDecay: time.Now(),
	}
}

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func (r *Reputation) AddSource(key, reason string) {
	if r == nil || !r.cfg.Enabled && r.cfg.Weights == nil {
		// Allow use without Enabled flag for testing convenience.
	}
	w := r.cfg.Weights[reason]
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.sources[key]
	now := time.Now()
	if !ok {
		e = &SourceEntry{FirstSeen: now, Events: make(map[string]int)}
		r.sources[key] = e
	}
	e.LastSeen = now
	e.Events[reason]++
	e.Score = clamp(e.Score + w)
}

func (r *Reputation) AddDest(ip string, port int, reason string, srcIP net.IP) {
	if r == nil {
		return
	}
	w := r.cfg.DestWeights[reason]
	r.mu.Lock()
	defer r.mu.Unlock()
	key := fmt.Sprintf("%s:%d", ip, port)
	e, ok := r.dests[key]
	now := time.Now()
	if !ok {
		e = &DestEntry{
			FirstSeen:   now,
			Events:      make(map[string]int),
			SeenSources: make(map[string]bool),
		}
		r.dests[key] = e
	}
	e.LastSeen = now
	e.Events[reason]++
	e.Score = clamp(e.Score + w)
	if srcIP != nil {
		s := srcIP.String()
		if !e.SeenSources[s] {
			e.SeenSources[s] = true
			e.DistinctSources++
			esc := r.cfg.DestWeights["distinctSourcesEscalation"]
			if esc != 0 {
				e.Score = clamp(e.Score + esc)
			}
		}
	}
}

func (r *Reputation) SourceScore(key string) int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.sources[key]; ok {
		return e.Score
	}
	return 0
}

func (r *Reputation) DestScore(ip string, port int) int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.dests[fmt.Sprintf("%s:%d", ip, port)]; ok {
		return e.Score
	}
	return 0
}

type Tier int

const (
	TierNormal Tier = iota
	TierWarn
	TierThrottle
	TierStrict
)

func (r *Reputation) Tier(score int) Tier {
	if r == nil {
		return TierNormal
	}
	t := r.cfg.Thresholds
	switch {
	case score >= t.Strict && t.Strict > 0:
		return TierStrict
	case score >= t.Throttle && t.Throttle > 0:
		return TierThrottle
	case score >= t.Warn && t.Warn > 0:
		return TierWarn
	}
	return TierNormal
}

type repSnapshot struct {
	Sources map[string]*SourceEntry `json:"sources"`
	Dests   map[string]*DestEntry   `json:"destinations"`
}

func (r *Reputation) SaveNow() error {
	if r == nil || r.cfg.StorePath == "" {
		return nil
	}
	r.mu.RLock()
	snap := repSnapshot{Sources: r.sources, Dests: r.dests}
	data, err := json.MarshalIndent(snap, "", "  ")
	r.mu.RUnlock()
	if err != nil {
		return err
	}
	dir := filepath.Dir(r.cfg.StorePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := r.cfg.StorePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.cfg.StorePath)
}

func (r *Reputation) Load() error {
	if r == nil || r.cfg.StorePath == "" {
		return nil
	}
	data, err := os.ReadFile(r.cfg.StorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap repSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	r.mu.Lock()
	if snap.Sources != nil {
		r.sources = snap.Sources
	}
	if snap.Dests != nil {
		r.dests = snap.Dests
	}
	r.mu.Unlock()
	return nil
}

// ForceDecay subtracts decayPerHour * (elapsed/hour) from every entry.
// Exposed for tests; production code uses a goroutine.
func (r *Reputation) ForceDecay(elapsed time.Duration) {
	if r == nil {
		return
	}
	if r.cfg.DecayPerHour == 0 {
		return
	}
	delta := int(float64(r.cfg.DecayPerHour) * elapsed.Hours())
	if delta <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.sources {
		e.Score = clamp(e.Score - delta)
	}
	for _, e := range r.dests {
		e.Score = clamp(e.Score - delta)
	}
	r.lastDecay = time.Now()
}

func (r *Reputation) RunMaintenance(stop <-chan struct{}, saveEvery time.Duration) {
	if r == nil {
		return
	}
	t := time.NewTicker(saveEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			_ = r.SaveNow()
			return
		case <-t.C:
			now := time.Now()
			r.ForceDecay(now.Sub(r.lastDecay))
			_ = r.SaveNow()
		}
	}
}
```

Add at the top of the file `import "fmt"`.

- [ ] **Step 6.4: Run, expect PASS**

Run: `go test ./wisp -run TestReputation -v -race`

- [ ] **Step 6.5: Commit**

```bash
git add wisp/reputation.go wisp/reputation_test.go wisp/limits.go
git commit -m "wisp: add reputation store with JSON persistence and score decay"
```


---

## Task 7: SYN-flood signature detector

**Files:**
- Create: `wisp/signature.go` (replacing the `Signatures` stub from Task 5)
- Create: `wisp/signature_test.go`

- [ ] **Step 7.1: Write failing tests**

Create `wisp/signature_test.go`:

```go
package wisp

import (
	"testing"
	"time"
)

func TestSignatureNoMatchOnSuccess(t *testing.T) {
	s := NewSignatures(SignatureConfig{
		Enabled:              true,
		Window:               2 * time.Second,
		MinSamples:           4,
		FailedHandshakeRatio: 0.75,
	})
	d := s.For(1, "9.9.9.9", 80)
	for i := 0; i < 10; i++ {
		d.Record(true)
	}
	if d.Match() {
		t.Fatal("should not match when all succeed")
	}
}

func TestSignatureMatchOnFailures(t *testing.T) {
	s := NewSignatures(SignatureConfig{
		Enabled:              true,
		Window:               2 * time.Second,
		MinSamples:           4,
		FailedHandshakeRatio: 0.75,
	})
	d := s.For(1, "9.9.9.9", 80)
	for i := 0; i < 10; i++ {
		d.Record(false)
	}
	if !d.Match() {
		t.Fatal("should match")
	}
}

func TestSignatureBelowMinSamples(t *testing.T) {
	s := NewSignatures(SignatureConfig{
		Enabled:              true,
		Window:               2 * time.Second,
		MinSamples:           10,
		FailedHandshakeRatio: 0.5,
	})
	d := s.For(1, "x", 1)
	d.Record(false)
	d.Record(false)
	if d.Match() {
		t.Fatal("below min samples")
	}
}
```

- [ ] **Step 7.2: Run, expect FAIL**

Run: `go test ./wisp -run TestSignature -v`
Expected: undefined.

- [ ] **Step 7.3: Replace stub with implementation**

Delete `type Signatures struct{}` from `wisp/limits.go`.

Create `wisp/signature.go`:

```go
package wisp

import (
	"fmt"
	"sync"
	"time"
)

type SignatureConfig struct {
	Enabled              bool
	Window               time.Duration
	MinSamples           int
	FailedHandshakeRatio float64
}

type Signatures struct {
	cfg SignatureConfig
	mu  sync.Mutex
	per map[string]*Detector
}

func NewSignatures(cfg SignatureConfig) *Signatures {
	return &Signatures{cfg: cfg, per: make(map[string]*Detector)}
}

func (s *Signatures) For(connID uint64, dstIP string, dstPort int) *Detector {
	if s == nil || !s.cfg.Enabled {
		return nopDetector
	}
	key := fmt.Sprintf("%d|%s:%d", connID, dstIP, dstPort)
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.per[key]
	if !ok {
		d = &Detector{cfg: s.cfg, ring: make([]sample, 0, s.cfg.MinSamples*2)}
		s.per[key] = d
	}
	return d
}

func (s *Signatures) Forget(connID uint64) {
	if s == nil {
		return
	}
	prefix := fmt.Sprintf("%d|", connID)
	s.mu.Lock()
	for k := range s.per {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(s.per, k)
		}
	}
	s.mu.Unlock()
}

type sample struct {
	t  time.Time
	ok bool
}

type Detector struct {
	cfg  SignatureConfig
	mu   sync.Mutex
	ring []sample
}

var nopDetector = &Detector{}

func (d *Detector) Record(ok bool) {
	if d == nil || d.cfg.Window == 0 {
		return
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ring = append(d.ring, sample{now, ok})
	cutoff := now.Add(-d.cfg.Window)
	for len(d.ring) > 0 && d.ring[0].t.Before(cutoff) {
		d.ring = d.ring[1:]
	}
}

func (d *Detector) Match() bool {
	if d == nil || d.cfg.Window == 0 {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.ring) < d.cfg.MinSamples {
		return false
	}
	failed := 0
	for _, s := range d.ring {
		if !s.ok {
			failed++
		}
	}
	ratio := float64(failed) / float64(len(d.ring))
	return ratio >= d.cfg.FailedHandshakeRatio
}
```

- [ ] **Step 7.4: Run, expect PASS**

Run: `go test ./wisp -run TestSignature -v -race`

- [ ] **Step 7.5: Commit**

```bash
git add wisp/signature.go wisp/signature_test.go wisp/limits.go
git commit -m "wisp: add SYN-flood signature detector"
```


---

## Task 8: Wire enforcement pipeline into handleConnectPacket / handleConnect

**Files:**
- Modify: `wisp/wisp.go` (Globals construction)
- Modify: `wisp/wisp-connection.go` (srcIP, globals, enforcement pipeline, structured log)
- Modify: `wisp/wisp-stream.go` (egress check after DNS, semaphore around dial, signature outcome, reputation update)

This is the integration task. Each step has the change spelled out exactly.

- [ ] **Step 8.1: Add a `connID` counter and `srcIP` to wispConnection**

Edit `wisp/wisp-connection.go`. At the top of the file add:

```go
var connIDCounter uint64
```

Modify struct:

```go
type wispConnection struct {
	netConn        net.Conn
	writeCh        chan writeReq
	streams        sync.Map
	cachedStreamId uint32
	cachedStream   unsafe.Pointer
	isClosed       atomic.Bool
	config         *Config
	twispStreams   *twispRegistry
	connectLimiter *connectRateLimiter
	globals        *Globals
	srcIP          net.IP
	connID         uint64
	violations     atomic.Int32
	streamCount    atomic.Int32

	isV2          bool
	handshakeDone chan struct{}
	streamConfirm bool
	v2Challenge   []byte
	writeDone     chan struct{}
	writeOnce     sync.Once
}
```

- [ ] **Step 8.2: Build Globals in CreateWispHandler**

Edit `wisp/wisp.go`. After `config.InitResolver()`, add:

```go
config.buildGlobals()
```

Add new method (in `wisp/wisp.go` or a new spot in `wisp/limits.go`):

```go
func (c *Config) buildGlobals() {
	if c.Globals != nil {
		return
	}
	g := &Globals{Egress: c.Egress}
	if c.FloodProtection != nil && c.FloodProtection.Enabled {
		fp := c.FloodProtection
		if fp.MaxConnectsPerSourceIPPerSecond > 0 {
			g.PerSource = NewSlidingWindow(fp.MaxConnectsPerSourceIPPerSecond, time.Second)
		}
		if fp.MaxConnectsPerDestPerSecond > 0 {
			g.PerDestSec = NewSlidingWindow(fp.MaxConnectsPerDestPerSecond, time.Second)
		}
		if fp.MaxConnectsPerDestPerMinute > 0 {
			g.PerDestMin = NewSlidingWindow(fp.MaxConnectsPerDestPerMinute, time.Minute)
		}
		if fp.MaxInFlightSyns > 0 {
			g.InFlightSyns = NewSemaphore(fp.MaxInFlightSyns)
		}
		if fp.MaxConcurrentConnections > 0 {
			g.Connections = NewSemaphore(fp.MaxConcurrentConnections)
		}
		g.Signature = NewSignatures(SignatureConfig{
			Enabled:              fp.SynFloodSignature.Enabled,
			Window:               time.Duration(fp.SynFloodSignature.WindowMs) * time.Millisecond,
			MinSamples:           fp.SynFloodSignature.MinSamples,
			FailedHandshakeRatio: fp.SynFloodSignature.FailedHandshakeRatio,
		})
	}
	if c.Reputation != nil && c.Reputation.Enabled {
		g.Reputation = NewReputation(*c.Reputation)
		_ = g.Reputation.Load()
	}
	c.Globals = g
}
```

Add to `Config`:

```go
type FloodProtectionConfig struct {
	Enabled                            bool
	MaxConnectsPerSourceIPPerSecond    int
	MaxConnectsPerDestPerSecond        int
	MaxConnectsPerDestPerMinute        int
	MaxInFlightSyns                    int
	MaxConcurrentStreamsPerConnection  int
	MaxConcurrentConnections           int
	SynFloodSignature                  struct {
		Enabled              bool
		WindowMs             int
		MinSamples           int
		FailedHandshakeRatio float64
	}
	WsCloseAfterViolations int
	LogBlockedDials        bool
}

type Config struct {
	// ... existing fields ...
	FloodProtection *FloodProtectionConfig
	Reputation      *ReputationConfig
	Globals         *Globals
	MaxPayloadBytes int
}
```

- [ ] **Step 8.3: Cap concurrent WS connections at upgrade**

Edit the handler returned by `CreateWispHandler`:

```go
return func(w http.ResponseWriter, r *http.Request) {
	if config.Globals != nil && config.Globals.Connections != nil && !config.Globals.Connections.TryAcquire() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	useV2 := config.EnableV2 && r.Header.Get("Sec-WebSocket-Protocol") != ""

	wsConn, err := upgrader.Upgrade(w, r)
	if err != nil {
		if config.Globals != nil && config.Globals.Connections != nil {
			config.Globals.Connections.Release()
		}
		return
	}

	netConn := wsConn.NetConn()

	if tc, ok := netConn.(*net.TCPConn); ok {
		if config.WebsocketTcpNoDelay {
			tc.SetNoDelay(true)
		}
		tc.SetReadBuffer(1 << 20)
		tc.SetWriteBuffer(1 << 20)
	}

	srcIP := ResolveClientIP(r, config.TrustedProxies, config.TrustedHeaders)

	wc := &wispConnection{
		netConn:        netConn,
		writeCh:        make(chan writeReq, 4096),
		config:         config,
		twispStreams:   newTwisp(),
		isV2:           useV2,
		connectLimiter: newConnectRateLimiter(config.MaxConnectsPerSecond),
		globals:        config.Globals,
		srcIP:          srcIP,
		connID:         atomic.AddUint64(&connIDCounter, 1),
	}
	wc.initWriteLifecycle()

	go wc.writeLoop()

	if useV2 {
		go wc.v2Handshake()
	} else {
		wc.sendPacket(0, config.BufferRemainingLength)
		go wc.readLoop()
	}
}
```

Also release the Connections semaphore in `deleteAllWispStreams`:

```go
func (c *wispConnection) deleteAllWispStreams() {
	c.isClosed.Store(true)
	c.streams.Range(...) // unchanged
	if c.twispStreams != nil { ... } // unchanged
	c.writeOnce.Do(func() {
		close(c.writeDone)
		close(c.writeCh)
	})
	if c.globals != nil && c.globals.Connections != nil {
		c.globals.Connections.Release()
	}
	if c.globals != nil && c.globals.Signature != nil {
		c.globals.Signature.Forget(c.connID)
	}
}
```

- [ ] **Step 8.4: Add structured-log helper**

In a new file `wisp/log.go`:

```go
package wisp

import (
	"encoding/json"
	"log"
	"time"
)

func logEvent(event string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["ts"] = time.Now().UTC().Format(time.RFC3339)
	fields["event"] = event
	b, err := json.Marshal(fields)
	if err != nil {
		return
	}
	log.Println(string(b))
}
```

- [ ] **Step 8.5: Replace handleConnectPacket with the enforcement pipeline**

Edit `wisp/wisp-connection.go`. Replace `handleConnectPacket`:

```go
func (c *wispConnection) handleConnectPacket(streamId uint32, payload []byte) {
	if !c.connectLimiter.allow() {
		c.violation("per_ws_rate")
		c.sendClosePacket(streamId, closeReasonThrottled)
		return
	}
	if len(payload) < 3 {
		return
	}
	streamType := payload[0]
	port := int(binary.LittleEndian.Uint16(payload[1:3]))
	hostname := string(payload[3:])

	srcKey := c.srcIP.String()

	// Per-connection concurrent stream cap.
	if c.config.FloodProtection != nil && c.config.FloodProtection.MaxConcurrentStreamsPerConnection > 0 {
		if c.streamCount.Load() >= int32(c.config.FloodProtection.MaxConcurrentStreamsPerConnection) {
			c.violation("per_ws_streams")
			c.sendClosePacket(streamId, closeReasonThrottled)
			return
		}
	}

	// Per-source IP rate.
	if c.globals != nil && c.globals.PerSource != nil && !c.globals.PerSource.Allow(srcKey) {
		c.violation("per_source_rate")
		c.repAddSource("burstRate")
		c.sendClosePacket(streamId, closeReasonThrottled)
		return
	}

	if streamType == streamTypeTerm {
		if !c.config.EnableTwisp {
			c.sendClosePacket(streamId, closeReasonBlocked)
			return
		}
		// Require auth for twisp (Task 10 enforces this; for now, refuse if v1
		// or if v2 auth wasn't passed).
		if !c.isV2 || !c.authPassed() {
			c.repAddSource("twispNoAuth")
			c.sendClosePacket(streamId, closeReasonBlocked)
			return
		}
		go handleTwisp(c, streamId, hostname)
		return
	}

	stream := &wispStream{
		wispConn:  c,
		streamId:  streamId,
		connReady: make(chan struct{}),
		hostname:  strings.ToLower(strings.TrimSpace(hostname)),
		port:      port,
	}
	stream.isOpen.Store(true)

	if _, loaded := c.streams.LoadOrStore(streamId, stream); loaded {
		close(stream.connReady)
		return
	}

	c.streamCount.Add(1)
	go stream.handleConnect(streamType, fmt.Sprintf("%d", port), hostname)
}

func (c *wispConnection) violation(reason string) {
	c.violations.Add(1)
	if c.config.FloodProtection != nil && c.config.FloodProtection.WsCloseAfterViolations > 0 {
		if c.violations.Load() >= int32(c.config.FloodProtection.WsCloseAfterViolations) {
			logEvent("ws_close_for_violations", map[string]any{
				"srcIP": c.srcIP.String(), "violations": c.violations.Load(), "reason": reason,
			})
			c.close()
		}
	}
}

func (c *wispConnection) repAddSource(reason string) {
	if c.globals != nil && c.globals.Reputation != nil && c.srcIP != nil {
		c.globals.Reputation.AddSource(c.srcIP.String(), reason)
	}
}

func (c *wispConnection) repAddDest(ip string, port int, reason string) {
	if c.globals != nil && c.globals.Reputation != nil {
		c.globals.Reputation.AddDest(ip, port, reason, c.srcIP)
	}
}

// authPassed returns true if v2 auth completed successfully. For now this is
// always true in v1 and is overridden in Task 10. For pre-Task-10 builds we
// keep the field optimistic to avoid breaking existing v2-without-auth flows.
func (c *wispConnection) authPassed() bool {
	return c.isV2 && c.handshakeDone != nil && isClosed(c.handshakeDone)
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
```

Add `import "fmt"` if not already present.

Add `port int` field to `wispStream` (in `wisp/wisp-stream.go`).

- [ ] **Step 8.6: Egress + dest rate + signature in handleConnect**

Edit `wisp/wisp-stream.go`. Replace `handleConnect`:

```go
func (s *wispStream) handleConnect(streamType uint8, port string, hostname string) {
	defer s.signalConnReady()
	defer s.wispConn.streamCount.Add(-1)

	cfg := s.wispConn.config
	c := s.wispConn
	s.hostname = strings.ToLower(strings.TrimSpace(hostname))

	if len(cfg.Whitelist.Hostnames) > 0 {
		if _, ok := cfg.Whitelist.Hostnames[s.hostname]; !ok {
			s.close(closeReasonBlocked)
			return
		}
	} else if len(cfg.Blacklist.Hostnames) > 0 {
		if _, ok := cfg.Blacklist.Hostnames[s.hostname]; ok {
			s.close(closeReasonBlocked)
			return
		}
	}

	if len(cfg.Whitelist.Ports) > 0 {
		if _, ok := cfg.Whitelist.Ports[port]; !ok {
			s.close(closeReasonBlocked)
			return
		}
	} else if len(cfg.Blacklist.Ports) > 0 {
		if _, ok := cfg.Blacklist.Ports[port]; ok {
			s.close(closeReasonBlocked)
			return
		}
	}

	// Resolve.
	resolvedIP := hostname
	if ip := net.ParseIP(hostname); ip != nil {
		// IP literal: skip DNS, but evaluate egress.
		if ok, reason := egressEvaluate(c.globals, ip); !ok {
			c.repAddSource("privateEgress")
			c.repAddDest(ip.String(), s.port, "privateEgress")
			logEvent("egress_block", map[string]any{
				"srcIP": c.srcIP.String(), "dstIP": ip.String(), "dstPort": s.port, "reason": reason,
			})
			s.close(closeReasonBlocked)
			return
		}
		resolvedIP = ip.String()
	} else if cfg.DNSCache != nil {
		if _, whitelisted := cfg.Whitelist.Hostnames[hostname]; !whitelisted {
			ips, err := cfg.DNSCache.LookupIPAddr(context.Background(), hostname)
			if err != nil || len(ips) == 0 {
				s.close(closeReasonUnreachable)
				return
			}
			picked := ""
			var pickedReason string
			for _, ip := range ips {
				if ok, reason := egressEvaluate(c.globals, ip.IP); ok {
					picked = ip.IP.String()
					break
				} else {
					pickedReason = reason
				}
			}
			if picked == "" {
				c.repAddSource("privateEgress")
				logEvent("egress_block", map[string]any{
					"srcIP": c.srcIP.String(), "host": hostname, "dstPort": s.port, "reason": pickedReason,
				})
				s.close(closeReasonBlocked)
				return
			}
			resolvedIP = picked
		}
	}

	// Per-destination rate (sec + min).
	dstKey := net.JoinHostPort(resolvedIP, port)
	if c.globals != nil {
		if c.globals.PerDestSec != nil && !c.globals.PerDestSec.Allow(dstKey) {
			c.violation("per_dest_sec")
			c.repAddSource("burstRate")
			c.repAddDest(resolvedIP, s.port, "burstRate")
			logEvent("flood_block", map[string]any{
				"srcIP": c.srcIP.String(), "dstIP": resolvedIP, "dstPort": s.port,
				"streamId": s.streamId, "reason": "per_dest_sec",
			})
			s.close(closeReasonThrottled)
			return
		}
		if c.globals.PerDestMin != nil && !c.globals.PerDestMin.Allow(dstKey) {
			c.violation("per_dest_min")
			s.close(closeReasonThrottled)
			return
		}
	}

	// Reputation-strict destination check.
	if c.globals != nil && c.globals.Reputation != nil {
		if c.globals.Reputation.Tier(c.globals.Reputation.DestScore(resolvedIP, s.port)) == TierStrict {
			c.repAddSource("requestKnownBadDest")
			logEvent("flood_block", map[string]any{
				"srcIP": c.srcIP.String(), "dstIP": resolvedIP, "dstPort": s.port,
				"streamId": s.streamId, "reason": "dest_reputation_strict",
			})
			s.close(closeReasonBlocked)
			return
		}
	}

	// In-flight SYN cap.
	if c.globals != nil && c.globals.InFlightSyns != nil {
		if !c.globals.InFlightSyns.TryAcquire() {
			c.violation("in_flight_syns")
			s.close(closeReasonThrottled)
			return
		}
		defer c.globals.InFlightSyns.Release()
	}

	s.streamType = streamType
	s.bufferRemaining = cfg.BufferRemainingLength

	destination := net.JoinHostPort(resolvedIP, port)

	var err error
	switch streamType {
	case streamTypeTCP:
		if cfg.Proxy != "" {
			dialer, proxyErr := proxy.SOCKS5("tcp", cfg.Proxy, nil, proxy.Direct)
			if proxyErr != nil {
				s.close(closeReasonNetworkError)
				return
			}
			s.conn, err = dialer.Dial("tcp", destination)
		} else {
			s.conn, err = cfg.Dialer.Dial("tcp", destination)
		}
	case streamTypeUDP:
		if cfg.DisableUDP || cfg.Proxy != "" {
			s.close(closeReasonBlocked)
			return
		}
		s.conn, err = net.Dial("udp", destination)
	default:
		s.close(closeReasonInvalidInfo)
		return
	}

	// Record dial outcome for SYN-flood signature.
	if c.globals != nil && c.globals.Signature != nil && streamType == streamTypeTCP {
		det := c.globals.Signature.For(c.connID, resolvedIP, s.port)
		det.Record(err == nil)
		if det.Match() {
			c.repAddSource("synSignature")
			c.repAddDest(resolvedIP, s.port, "synSignature")
			logEvent("syn_signature", map[string]any{
				"srcIP": c.srcIP.String(), "dstIP": resolvedIP, "dstPort": s.port, "streamId": s.streamId,
			})
			if err == nil {
				s.conn.Close()
			}
			s.close(closeReasonBlocked)
			c.close()
			return
		}
	}

	if err != nil {
		s.close(mapDialError(err))
		return
	}

	if streamType == streamTypeTCP {
		if tc, ok := s.conn.(*net.TCPConn); ok {
			tc.SetNoDelay(cfg.TcpNoDelay)
			tc.SetReadBuffer(1 << 20)
			tc.SetWriteBuffer(1 << 20)
		}
	}

	if s.wispConn.streamConfirm && streamType == streamTypeTCP {
		s.wispConn.sendPacket(s.streamId, s.bufferRemaining)
	}

	s.signalConnReady()

	s.pendingMutex.Lock()
	pending := s.pendingData
	s.pendingData = nil
	s.pendingMutex.Unlock()
	for _, data := range pending {
		if !s.isOpen.Load() {
			return
		}
		if _, err := s.conn.Write(data); err != nil {
			s.close(closeReasonNetworkError)
			return
		}
	}

	s.readFromConnection()
}

func egressEvaluate(g *Globals, ip net.IP) (bool, string) {
	if g == nil || g.Egress == nil {
		return true, ""
	}
	return g.Egress.Evaluate(ip)
}
```

Replace the existing `defer s.signalConnReady()` line (it's now at the top of the new function).

- [ ] **Step 8.7: Compile**

Run: `go build ./...`
Expected: success.

- [ ] **Step 8.8: Run all wisp tests**

Run: `go test ./wisp -v -race`
Expected: all PASS.

- [ ] **Step 8.9: Commit**

```bash
git add wisp/
git commit -m "wisp: enforcement pipeline (per-source/dest rate, egress, semaphore, reputation, signature)"
```


---

## Task 9: Constant-time password compare + optional bcrypt

**Files:**
- Modify: `wisp/v2.go`
- Create: `wisp/v2_test.go`
- Modify: `go.mod` / `go.sum` (add `golang.org/x/crypto`)

- [ ] **Step 9.1: Add dependency**

Run: `go get golang.org/x/crypto/bcrypt`

- [ ] **Step 9.2: Write failing tests**

Create `wisp/v2_test.go`:

```go
package wisp

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCheckPasswordPlaintext(t *testing.T) {
	if !checkPassword("hunter2", "hunter2") {
		t.Fatal("plain match")
	}
	if checkPassword("hunter2", "hunter3") {
		t.Fatal("plain mismatch should fail")
	}
}

func TestCheckPasswordBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !checkPassword(string(hash), "s3cret") {
		t.Fatal("bcrypt match")
	}
	if checkPassword(string(hash), "wrong") {
		t.Fatal("bcrypt mismatch should fail")
	}
}
```

- [ ] **Step 9.3: Run, expect FAIL**

Run: `go test ./wisp -run TestCheckPassword -v`
Expected: undefined: checkPassword.

- [ ] **Step 9.4: Implement**

Edit `wisp/v2.go`. Add at top:

```go
import (
	"crypto/subtle"
	"strings"

	"golang.org/x/crypto/bcrypt"
)
```

Add function:

```go
func checkPassword(stored, provided string) bool {
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(provided)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) == 1
}
```

Replace the password block in `handleInfo`:

```go
if c.config.PasswordAuth && clientExts.passwordUsername != "" {
	expectedPassword, userExists := c.config.PasswordUsers[clientExts.passwordUsername]
	if userExists && checkPassword(expectedPassword, clientExts.passwordPassword) {
		authPassed = true
	} else {
		c.sendClosePacket(0, closeReasonAuthBadPassword)
		c.close()
		return
	}
}
```

- [ ] **Step 9.5: Run, expect PASS**

Run: `go test ./wisp -run TestCheckPassword -v -race`

- [ ] **Step 9.6: Commit**

```bash
git add wisp/v2.go wisp/v2_test.go go.mod go.sum
git commit -m "wisp/v2: constant-time password compare, optional bcrypt"
```


---

## Task 10: Lock Twisp behind required auth

**Files:**
- Modify: `wisp/twisp.go`
- Modify: `wisp/wisp-connection.go` (auth tracking)

The Task 8 pipeline already calls `c.authPassed()` before allowing twisp. This task hardens that check.

- [ ] **Step 10.1: Add authPassed atomic flag**

Edit `wisp/wisp-connection.go`. Add to struct:

```go
authPassedFlag atomic.Bool
```

Remove the temporary `authPassed()` helper from Task 8 (the one that returned `isClosed(handshakeDone)`). Replace:

```go
func (c *wispConnection) authPassed() bool {
	return c.authPassedFlag.Load()
}
```

- [ ] **Step 10.2: Set the flag in handleInfo**

Edit `wisp/v2.go` `handleInfo`. After the auth checks pass, before `close(c.handshakeDone)`:

```go
if authPassed || (!c.config.PasswordAuthRequired && !c.config.CertAuthRequired) {
	if authPassed {
		c.authPassedFlag.Store(true)
	}
}
```

Actually simpler — set the flag in two specific spots:

```go
// After successful password check:
if userExists && checkPassword(expectedPassword, clientExts.passwordPassword) {
	authPassed = true
	c.authPassedFlag.Store(true)
}

// After successful cert check:
if c.verifyCertificate(clientExts) {
	authPassed = true
	c.authPassedFlag.Store(true)
}
```

- [ ] **Step 10.3: Tighten twisp gate**

Edit `wisp/wisp-connection.go` (the `streamType == streamTypeTerm` branch added in Task 8). Replace:

```go
if streamType == streamTypeTerm {
	if !c.config.EnableTwisp {
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	// Require auth if any auth method is enabled. v1 has no auth, so refuse.
	if !c.isV2 {
		c.repAddSource("twispNoAuth")
		logEvent("twisp_blocked", map[string]any{"srcIP": c.srcIP.String(), "reason": "v1_no_auth"})
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	if (c.config.PasswordAuth || c.config.CertAuth) && !c.authPassed() {
		c.repAddSource("twispNoAuth")
		logEvent("twisp_blocked", map[string]any{"srcIP": c.srcIP.String(), "reason": "not_authenticated"})
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	if !c.config.PasswordAuth && !c.config.CertAuth {
		// Twisp enabled but server has no auth at all: refuse.
		c.repAddSource("twispNoAuth")
		logEvent("twisp_blocked", map[string]any{"srcIP": c.srcIP.String(), "reason": "no_auth_configured"})
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	go handleTwisp(c, streamId, hostname)
	return
}
```

- [ ] **Step 10.4: Add test**

Append to `wisp/v2_test.go`:

```go
func TestTwispGateNoAuth(t *testing.T) {
	c := &wispConnection{
		config: &Config{EnableTwisp: true, PasswordAuth: false, CertAuth: false},
		isV2:   true,
	}
	if c.authPassed() {
		t.Fatal("unauthenticated v2 should not pass")
	}
}
```

- [ ] **Step 10.5: Run all tests**

Run: `go test ./wisp -v -race`

- [ ] **Step 10.6: Commit**

```bash
git add wisp/
git commit -m "wisp/twisp: gate behind required auth, log unauthenticated attempts"
```


---

## Task 11: main.go — config sub-structs, file-only -config, HTTP timeouts

**Files:**
- Modify: `main.go`

- [ ] **Step 11.1: Add new config types and defaults**

Edit `main.go`. Replace `Config` struct with:

```go
type FloodSig struct {
	Enabled              bool    `json:"enabled"`
	WindowMs             int     `json:"windowMs"`
	MinSamples           int     `json:"minSamples"`
	FailedHandshakeRatio float64 `json:"failedHandshakeRatio"`
}

type FloodCfg struct {
	Enabled                            bool     `json:"enabled"`
	MaxConnectsPerSourceIPPerSecond    int      `json:"maxConnectsPerSourceIPPerSecond"`
	MaxConnectsPerDestPerSecond        int      `json:"maxConnectsPerDestPerSecond"`
	MaxConnectsPerDestPerMinute        int      `json:"maxConnectsPerDestPerMinute"`
	MaxInFlightSyns                    int      `json:"maxInFlightSyns"`
	MaxConcurrentStreamsPerConnection  int      `json:"maxConcurrentStreamsPerConnection"`
	MaxConcurrentConnections           int      `json:"maxConcurrentConnections"`
	SynFloodSignature                  FloodSig `json:"synFloodSignature"`
	WsCloseAfterViolations             int      `json:"wsCloseAfterViolations"`
	LogBlockedDials                    bool     `json:"logBlockedDials"`
}

type ReputationCfg struct {
	Enabled             bool           `json:"enabled"`
	StorePath           string         `json:"storePath"`
	SaveIntervalSeconds int            `json:"saveIntervalSeconds"`
	ScoreDecayPerHour   int            `json:"scoreDecayPerHour"`
	EvictAfterDays      int            `json:"evictAfterDays"`
	Thresholds          struct {
		Warn     int `json:"warn"`
		Throttle int `json:"throttle"`
		Strict   int `json:"strict"`
	} `json:"thresholds"`
	Weights     map[string]int `json:"weights"`
	DestWeights map[string]int `json:"destinationWeights"`
}

type EgressCfg struct {
	AllowPrivate bool     `json:"allowPrivate"`
	AllowIPs     []string `json:"allowIPs"`
	AllowCIDRs   []string `json:"allowCIDRs"`
	DenyIPs      []string `json:"denyIPs"`
	DenyCIDRs    []string `json:"denyCIDRs"`
}

type Config struct {
	Port                  int    `json:"port"`
	DisableUDP            bool   `json:"disableUDP"`
	TcpBufferSize         int    `json:"tcpBufferSize"`
	BufferRemainingLength uint32 `json:"bufferRemainingLength"`
	TcpNoDelay            bool   `json:"tcpNoDelay"`
	WebsocketTcpNoDelay   bool   `json:"websocketTcpNoDelay"`
	MaxPayloadBytes       int    `json:"maxPayloadBytes"`

	Blacklist struct {
		Hostnames []string `json:"hostnames"`
		Ports     []int    `json:"ports"`
	} `json:"blacklist"`
	Whitelist struct {
		Hostnames []string `json:"hostnames"`
		Ports     []int    `json:"ports"`
	} `json:"whitelist"`

	Proxy                      string   `json:"proxy"`
	WebsocketPermessageDeflate bool     `json:"websocketPermessageDeflate"`
	DnsServers                 []string `json:"dnsServers"`
	DnsServerLegacy            []string `json:"dnsServer"` // backward-compat

	EnableTwisp bool `json:"enableTwisp"`

	EnableV2             bool              `json:"enableV2"`
	Motd                 string            `json:"motd"`
	PasswordAuth         bool              `json:"passwordAuth"`
	PasswordAuthRequired bool              `json:"passwordAuthRequired"`
	PasswordUsers        map[string]string `json:"passwordUsers"`
	CertAuth             bool              `json:"certAuth"`
	CertAuthRequired     bool              `json:"certAuthRequired"`
	CertAuthPublicKeys   []string          `json:"certAuthPublicKeys"`
	EnableStreamConfirm  bool              `json:"enableStreamConfirm"`
	MaxConnectsPerSecond int               `json:"maxConnectsPerSecond"`

	TrustedProxies []string `json:"trustedProxies"`
	TrustedHeaders []string `json:"trustedHeaders"`

	FloodProtection *FloodCfg      `json:"floodProtection"`
	Reputation      *ReputationCfg `json:"reputation"`
	Egress          *EgressCfg     `json:"egress"`
}
```

Update `defaultConfig()`:

```go
func defaultConfig() Config {
	c := Config{
		Port:                       6001,
		DisableUDP:                 false,
		TcpBufferSize:              32768,
		BufferRemainingLength:      65536,
		TcpNoDelay:                 true,
		WebsocketTcpNoDelay:        true,
		MaxPayloadBytes:            1 << 20,
		WebsocketPermessageDeflate: false,
		EnableTwisp:                false,
		EnableV2:                   false,
		PasswordAuth:               false,
		PasswordAuthRequired:       false,
		PasswordUsers:              make(map[string]string),
		CertAuth:                   false,
		CertAuthRequired:           false,
		EnableStreamConfirm:        false,
		TrustedHeaders:             []string{"CF-Connecting-IP", "X-Forwarded-For"},
	}
	fp := FloodCfg{
		Enabled:                           true,
		MaxConnectsPerSourceIPPerSecond:   50,
		MaxConnectsPerDestPerSecond:       8,
		MaxConnectsPerDestPerMinute:       60,
		MaxInFlightSyns:                   256,
		MaxConcurrentStreamsPerConnection: 256,
		MaxConcurrentConnections:          1024,
		WsCloseAfterViolations:            16,
		LogBlockedDials:                   true,
	}
	fp.SynFloodSignature = FloodSig{Enabled: true, WindowMs: 2000, MinSamples: 32, FailedHandshakeRatio: 0.75}
	c.FloodProtection = &fp

	rep := ReputationCfg{
		Enabled:             true,
		StorePath:           "./data/mrrowisp-reputation.json",
		SaveIntervalSeconds: 30,
		ScoreDecayPerHour:   1,
		EvictAfterDays:      7,
		Weights: map[string]int{
			"privateEgress":       15,
			"synSignature":        25,
			"twispNoAuth":         40,
			"burstRate":           5,
			"successfulStream":    -2,
			"requestKnownBadDest": 2,
		},
		DestWeights: map[string]int{
			"privateEgress":             20,
			"synSignature":              30,
			"distinctSourcesEscalation": 1,
		},
	}
	rep.Thresholds.Warn = 21
	rep.Thresholds.Throttle = 51
	rep.Thresholds.Strict = 81
	c.Reputation = &rep

	c.Egress = &EgressCfg{AllowPrivate: false}
	return c
}
```

- [ ] **Step 11.2: file-only -config, deprecate JSON string**

Replace the `loadConfig` function:

```go
func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	if strings.HasPrefix(strings.TrimSpace(path), "{") {
		fmt.Fprintln(os.Stderr, "warning: passing config JSON on the command line is deprecated and leaks secrets via process listings; use a file path instead.")
		if err := json.Unmarshal([]byte(path), &cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
```

Inside `createWispConfig`, merge legacy DNS key:

```go
dns := cfg.DnsServers
if len(dns) == 0 && len(cfg.DnsServerLegacy) > 0 {
	fmt.Fprintln(os.Stderr, "warning: 'dnsServer' is deprecated; rename to 'dnsServers'")
	dns = cfg.DnsServerLegacy
}
```

(then use `dns` in place of `cfg.DnsServers` in the wispCfg construction).

- [ ] **Step 11.3: Build wisp.Config from new fields**

In `createWispConfig`, add construction for the new sub-blocks:

```go
var floodCfg *wisp.FloodProtectionConfig
if cfg.FloodProtection != nil {
	fp := *cfg.FloodProtection
	floodCfg = &wisp.FloodProtectionConfig{
		Enabled:                           fp.Enabled,
		MaxConnectsPerSourceIPPerSecond:   fp.MaxConnectsPerSourceIPPerSecond,
		MaxConnectsPerDestPerSecond:       fp.MaxConnectsPerDestPerSecond,
		MaxConnectsPerDestPerMinute:       fp.MaxConnectsPerDestPerMinute,
		MaxInFlightSyns:                   fp.MaxInFlightSyns,
		MaxConcurrentStreamsPerConnection: fp.MaxConcurrentStreamsPerConnection,
		MaxConcurrentConnections:          fp.MaxConcurrentConnections,
		WsCloseAfterViolations:            fp.WsCloseAfterViolations,
		LogBlockedDials:                   fp.LogBlockedDials,
	}
	floodCfg.SynFloodSignature.Enabled = fp.SynFloodSignature.Enabled
	floodCfg.SynFloodSignature.WindowMs = fp.SynFloodSignature.WindowMs
	floodCfg.SynFloodSignature.MinSamples = fp.SynFloodSignature.MinSamples
	floodCfg.SynFloodSignature.FailedHandshakeRatio = fp.SynFloodSignature.FailedHandshakeRatio
}

var repCfg *wisp.ReputationConfig
if cfg.Reputation != nil {
	r := *cfg.Reputation
	rc := wisp.ReputationConfig{
		Enabled:      r.Enabled,
		StorePath:    r.StorePath,
		DecayPerHour: r.ScoreDecayPerHour,
		EvictAfter:   time.Duration(r.EvictAfterDays) * 24 * time.Hour,
		Weights:      r.Weights,
		DestWeights:  r.DestWeights,
	}
	rc.Thresholds.Warn = r.Thresholds.Warn
	rc.Thresholds.Throttle = r.Thresholds.Throttle
	rc.Thresholds.Strict = r.Thresholds.Strict
	repCfg = &rc
}

var egressPol *wisp.EgressPolicy
if cfg.Egress != nil {
	e := wisp.EgressPolicy{AllowPrivate: cfg.Egress.AllowPrivate}
	if len(cfg.Egress.AllowIPs) > 0 {
		e.AllowIPs = make(map[string]struct{})
		for _, ip := range cfg.Egress.AllowIPs {
			e.AllowIPs[ip] = struct{}{}
		}
	}
	if len(cfg.Egress.DenyIPs) > 0 {
		e.DenyIPs = make(map[string]struct{})
		for _, ip := range cfg.Egress.DenyIPs {
			e.DenyIPs[ip] = struct{}{}
		}
	}
	for _, c := range cfg.Egress.AllowCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			e.AllowCIDRs = append(e.AllowCIDRs, n)
		}
	}
	for _, c := range cfg.Egress.DenyCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			e.DenyCIDRs = append(e.DenyCIDRs, n)
		}
	}
	egressPol = &e
}

var trustedNets []*net.IPNet
for _, t := range cfg.TrustedProxies {
	if !strings.Contains(t, "/") {
		// bare IP -> /32 or /128
		if ip := net.ParseIP(t); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			t = fmt.Sprintf("%s/%d", t, bits)
		}
	}
	if _, n, err := net.ParseCIDR(t); err == nil {
		trustedNets = append(trustedNets, n)
	}
}
```

Add these fields to the `wispCfg := &wisp.Config{...}` literal:

```go
wispCfg.MaxPayloadBytes = cfg.MaxPayloadBytes
wispCfg.TrustedProxies = trustedNets
wispCfg.TrustedHeaders = cfg.TrustedHeaders
wispCfg.FloodProtection = floodCfg
wispCfg.Reputation = repCfg
wispCfg.Egress = egressPol
```

- [ ] **Step 11.4: HTTP server with timeouts**

Replace the bottom of `main()`:

```go
wispHandler := wisp.CreateWispHandler(wispConfig)

mux := http.NewServeMux()
mux.HandleFunc("/", wispHandler)

srv := &http.Server{
	Addr:              fmt.Sprintf(":%d", cfg.Port),
	Handler:           mux,
	ReadHeaderTimeout: 10 * time.Second,
	ReadTimeout:       30 * time.Second,
	IdleTimeout:       120 * time.Second,
}

// Start reputation maintenance.
stop := make(chan struct{})
if wispConfig.Globals != nil && wispConfig.Globals.Reputation != nil && cfg.Reputation != nil {
	saveEvery := time.Duration(cfg.Reputation.SaveIntervalSeconds) * time.Second
	if saveEvery <= 0 {
		saveEvery = 30 * time.Second
	}
	go wispConfig.Globals.Reputation.RunMaintenance(stop, saveEvery)
}

fmt.Printf("Starting Mrrowisp on port %d. . .", cfg.Port)
if err := srv.ListenAndServe(); err != nil {
	fmt.Printf("Failed to start Mrrowisp: %v", err)
}
close(stop)
```

Add the necessary imports (`net`, `time` already there; add nothing new).

- [ ] **Step 11.5: Build**

Run: `go build ./...`
Expected: success.

- [ ] **Step 11.6: Smoke test**

Run:

```bash
./mrrowisp -port 16001 &
PID=$!
sleep 1
# Healthcheck: GET / should respond (WS upgrade fails, but we should see a TCP connect)
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:16001/
kill $PID
```

Expected: a 4xx (WS upgrade failure on plain HTTP GET) without any panic. PID exits cleanly.

- [ ] **Step 11.7: Commit**

```bash
git add main.go
git commit -m "main: new config sub-structs, HTTP timeouts, reputation maintenance goroutine"
```


---

## Task 12: TypeScript wrapper — tempfile config, reuse WSS in route(), new types

**Files:**
- Modify: `src/types.d.ts`
- Modify: `src/server/index.ts`

- [ ] **Step 12.1: Extend the `Config` type**

Edit `src/types.d.ts`. Replace the `Config` type with:

```ts
export type FloodProtectionConfig = {
	enabled?: boolean;
	maxConnectsPerSourceIPPerSecond?: number;
	maxConnectsPerDestPerSecond?: number;
	maxConnectsPerDestPerMinute?: number;
	maxInFlightSyns?: number;
	maxConcurrentStreamsPerConnection?: number;
	maxConcurrentConnections?: number;
	synFloodSignature?: {
		enabled?: boolean;
		windowMs?: number;
		minSamples?: number;
		failedHandshakeRatio?: number;
	};
	wsCloseAfterViolations?: number;
	logBlockedDials?: boolean;
};

export type ReputationConfig = {
	enabled?: boolean;
	storePath?: string;
	saveIntervalSeconds?: number;
	scoreDecayPerHour?: number;
	evictAfterDays?: number;
	thresholds?: { warn?: number; throttle?: number; strict?: number };
	weights?: Record<string, number>;
	destinationWeights?: Record<string, number>;
};

export type EgressConfig = {
	allowPrivate?: boolean;
	allowIPs?: string[];
	allowCIDRs?: string[];
	denyIPs?: string[];
	denyCIDRs?: string[];
};

export type Config = {
	port?: number;
	disableUDP?: boolean;
	tcpBufferSize?: number;
	bufferRemainingLength?: number;
	tcpNoDelay?: boolean;
	websocketTcpNoDelay?: boolean;
	maxPayloadBytes?: number;
	blacklist?: { hostnames: string[]; ports?: number[]; };
	whitelist?: { hostnames: string[]; ports?: number[]; };
	proxy?: string;
	websocketPermessageDeflate?: boolean;
	dnsServers?: string[];
	dnsServer?: string[]; // legacy
	enableTwisp?: boolean;
	enableV2: boolean;
	motd?: string;
	passwordAuth?: boolean;
	passwordAuthRequired?: boolean;
	passwordUsers?: { [username: string]: string };
	certAuth?: boolean;
	certAuthRequired?: boolean;
	certAuthPublicKeys?: string[];
	enableStreamConfirm?: boolean;
	maxConnectsPerSecond?: number;
	trustedProxies?: string[];
	trustedHeaders?: string[];
	floodProtection?: FloodProtectionConfig;
	reputation?: ReputationConfig;
	egress?: EgressConfig;
};
```

(Keep `WispEvents`, `WispServer`, `WispBuilder`, `RouteRequest` unchanged.)

Add builder method signatures to `WispBuilder`:

```ts
floodProtection(cfg: FloodProtectionConfig): WispBuilder;
reputation(cfg: ReputationConfig): WispBuilder;
egress(cfg: EgressConfig): WispBuilder;
trustedProxies(cidrs: string[]): WispBuilder;
trustedHeaders(headers: string[]): WispBuilder;
maxPayloadBytes(bytes: number): WispBuilder;
```

- [ ] **Step 12.2: Implement tempfile config + new builders + WSS reuse**

Edit `src/server/index.ts`. Add imports:

```ts
import * as os from "os";
import * as path from "path";
```

Replace the `route` method to reuse a single WSS (lazily created):

```ts
private wss?: WebSocketServer;

route(req: IncomingMessage, socket: net.Socket, head: Buffer): void {
	const port = this.config.port ?? 8080;
	if (!this.wss) {
		this.wss = new WebSocketServer({ noServer: true });
	}
	const wss = this.wss;

	wss.handleUpgrade(req, socket, head, (ws: WebSocket) => {
		const client = new WebSocket(`ws://localhost:${port}`);

		client.on("open", () => {
			ws.on("message", (data: Buffer) => {
				if (client.readyState === WebSocket.OPEN) client.send(data);
			});
			ws.on("close", () => client.close());
			ws.on("error", () => client.close());
		});

		client.on("message", (data: Buffer) => {
			if (ws.readyState === ws.OPEN) ws.send(data);
		});
		client.on("close", () => ws.close());
		client.on("error", (err) => ws.close(1011, err.message));
	});

	socket.on("error", () => { /* keep wss alive */ });
}
```

Add the new builder methods (anywhere in `WispBuilderImpl`):

```ts
floodProtection(cfg: FloodProtectionConfig): WispBuilder {
	this.config.floodProtection = { ...this.config.floodProtection, ...cfg };
	return this;
}
reputation(cfg: ReputationConfig): WispBuilder {
	this.config.reputation = { ...this.config.reputation, ...cfg };
	return this;
}
egress(cfg: EgressConfig): WispBuilder {
	this.config.egress = { ...this.config.egress, ...cfg };
	return this;
}
trustedProxies(cidrs: string[]): WispBuilder {
	this.config.trustedProxies = cidrs;
	return this;
}
trustedHeaders(headers: string[]): WispBuilder {
	this.config.trustedHeaders = headers;
	return this;
}
maxPayloadBytes(bytes: number): WispBuilder {
	this.config.maxPayloadBytes = bytes;
	return this;
}
```

Add imports for the new config types:

```ts
import type { Config, WispBuilder, WispEvents, WispServer, RouteRequest, FloodProtectionConfig, ReputationConfig, EgressConfig } from "../types.js";
```

Replace `start()`:

```ts
start(): Promise<WispServer> {
	return new Promise((resolve, reject) => {
		let resolved = false;

		// Write config to a private temp file rather than passing via argv.
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mrrowisp-"));
		const cfgPath = path.join(dir, "config.json");
		fs.writeFileSync(cfgPath, JSON.stringify(this.config), { mode: 0o600 });

		const process = spawn(wispPath, ["--config", cfgPath]);

		const cleanup = () => {
			try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
		};

		const server = new WispServerImpl(process, this.config, this.listeners);

		process.stdout.on("data", (data: Buffer) => {
			const str = data.toString();
			this.listeners.stdout.forEach((cb) => cb(str));
			if (!resolved && str.includes("Starting Mrrowisp")) {
				resolved = true;
				this.listeners.ready.forEach((cb) => cb());
				resolve(server);
			}
		});

		process.stderr.on("data", (data: Buffer) => {
			const str = data.toString();
			this.listeners.stderr.forEach((cb) => cb(str));
		});

		process.on("error", (err) => {
			cleanup();
			if (!resolved) {
				resolved = true;
				this.listeners.error.forEach((cb) => cb(err));
				reject(err);
			}
		});

		process.on("exit", (code, signal) => {
			cleanup();
			if (!resolved) {
				resolved = true;
				const err = new Error(`Server exited before ready (code: ${code}, signal: ${signal})`);
				this.listeners.error.forEach((cb) => cb(err));
				reject(err);
			}
		});

		setTimeout(() => {
			if (!resolved) {
				resolved = true;
				const err = new Error("Server startup timed out after 10 seconds");
				this.listeners.error.forEach((cb) => cb(err));
				process.kill("SIGKILL");
				cleanup();
				reject(err);
			}
		}, 10000);
	});
}
```

Update the `dns(...)` builder so it always populates `dnsServers` (not the legacy key):

```ts
dns(servers: string | string[]): WispBuilder {
	this.config.dnsServers = Array.isArray(servers) ? servers : [servers];
	return this;
}
```

- [ ] **Step 12.3: Build TypeScript**

Run: `bun run build || npx tsc -p .`
Expected: success.

- [ ] **Step 12.4: Commit**

```bash
git add src/ tsconfig.json
git commit -m "ts: tempfile config, reuse WebSocketServer, add new config builders"
```


---

## Task 13: Docs — README + example.config.json

**Files:**
- Modify: `example.config.json`
- Modify: `README.md`

- [ ] **Step 13.1: Update example.config.json**

Replace the file contents:

```json
{
	"port": 6001,
	"disableUDP": false,
	"tcpBufferSize": 65535,
	"bufferRemainingLength": 1024,
	"tcpNoDelay": true,
	"websocketTcpNoDelay": true,
	"maxPayloadBytes": 1048576,
	"blacklist": { "hostnames": [], "ports": [] },
	"whitelist": { "hostnames": [], "ports": [] },
	"proxy": "",
	"websocketPermessageDeflate": false,
	"dnsServers": [],
	"enableTwisp": false,
	"enableV2": true,
	"motd": "",
	"passwordAuth": false,
	"passwordAuthRequired": false,
	"passwordUsers": {},
	"certAuth": false,
	"certAuthRequired": false,
	"certAuthPublicKeys": [],
	"enableStreamConfirm": false,
	"maxConnectsPerSecond": 20,
	"trustedProxies": [],
	"trustedHeaders": ["CF-Connecting-IP", "X-Forwarded-For"],
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

- [ ] **Step 13.2: Add README sections**

Append a new section to `README.md` between the existing Configuration Options table and the Credits section:

```markdown
### Flood protection & egress

mrrowisp now ships with default-deny SSRF protection and per-destination rate limiting to prevent the server from being abused as a TCP SYN flood relay. The defaults are appropriate for a public proxy; tune `floodProtection` and `egress` to suit your deployment.

**Behavior change in this version:** by default the server **refuses** outbound connections to private/loopback/link-local IP ranges (RFC1918, 127/8, 169.254/16, ::1, fc00::/7, fe80::/10). To allow them, either set `egress.allowPrivate: true` or list specific CIDRs in `egress.allowCIDRs`.

**Reputation:** the server tracks a 0-100 score per source IP and per destination `ip:port`. Bad behavior (egress violations, SYN-flood signatures, twisp without auth, repeated burst-rate hits) raises the score; long-lived successful streams lower it. When a source's score reaches `thresholds.strict` (default 81), CONNECTs to known-bad destinations are refused. The store is persisted to `reputation.storePath` and survives restarts.

**Structured logging:** every block emits a single-line JSON record on stderr — pipe to fail2ban or a log aggregator. Example regex for fail2ban:

```
failregex = "event":"flood_block".*"srcIP":"<HOST>"
```

| Option                                                         | Default | Description                               |
| -------------------------------------------------------------- | ------- | ----------------------------------------- |
| `maxPayloadBytes`                                              | 1048576 | Hard cap on a single WS frame payload     |
| `trustedProxies`                                               | `[]`    | CIDRs whose `X-Forwarded-For` is honored  |
| `trustedHeaders`                                               | CF-Connecting-IP, X-Forwarded-For | Headers consulted when peer is trusted |
| `floodProtection.maxConnectsPerSourceIPPerSecond`              | 50      | Per-source-IP CONNECT rate                |
| `floodProtection.maxConnectsPerDestPerSecond`                  | 8       | Per-destination-IP:port CONNECT rate      |
| `floodProtection.maxConnectsPerDestPerMinute`                  | 60      | Same destination, longer window           |
| `floodProtection.maxInFlightSyns`                              | 256     | Cap on concurrent unfinished dials        |
| `floodProtection.maxConcurrentStreamsPerConnection`            | 256     | Cap on concurrent streams per WS          |
| `floodProtection.maxConcurrentConnections`                     | 1024    | Cap on concurrent WS connections          |
| `floodProtection.synFloodSignature.enabled`                    | true    | Detect SYN-only outbound bursts           |
| `floodProtection.synFloodSignature.windowMs`                   | 2000    | Detection window                          |
| `floodProtection.synFloodSignature.minSamples`                 | 32      | Min dials in window before detection      |
| `floodProtection.synFloodSignature.failedHandshakeRatio`       | 0.75    | Failed-handshake fraction that triggers   |
| `floodProtection.wsCloseAfterViolations`                       | 16      | Close WS after this many enforcement hits |
| `egress.allowPrivate`                                          | false   | Allow private/loopback/link-local IPs     |
| `egress.allowIPs` / `egress.allowCIDRs`                        | `[]`    | Explicit allow overrides                  |
| `egress.denyIPs` / `egress.denyCIDRs`                          | `[]`    | Explicit deny (highest priority)          |
| `reputation.enabled`                                           | true    | Track source/dest reputation              |
| `reputation.storePath`                                         | ./data/mrrowisp-reputation.json | Persistence file       |
| `reputation.scoreDecayPerHour`                                 | 1       | Score decay rate                          |
| `reputation.thresholds.warn`/`throttle`/`strict`               | 21/51/81 | Tier breakpoints                         |
```

- [ ] **Step 13.3: Commit**

```bash
git add example.config.json README.md
git commit -m "docs: README and example config for flood protection, egress, reputation"
```

---

## Final verification

- [ ] **Run all Go tests once more under -race**

Run: `go test ./... -race -count=1`
Expected: all PASS.

- [ ] **Build the binary**

Run: `go build -o mrrowisp .`

- [ ] **Smoke test**

Run:
```bash
./mrrowisp -config example.config.json &
PID=$!
sleep 1
curl -sf http://127.0.0.1:6001/ -o /dev/null || true
kill $PID
wait $PID 2>/dev/null
```
Expected: process starts, prints the start banner, accepts the curl probe (returns a non-200 since there's no WS upgrade) without panicking, exits cleanly on SIGTERM.

- [ ] **Final commit (if any leftover changes)**

```bash
git status
# If clean, no commit needed.
```

