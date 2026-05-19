package wisp

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/proxy"
)

type wispStream struct {
	wispConn *wispConnection

	streamId        uint32
	streamType      uint8
	conn            net.Conn
	bufferRemaining uint32
	hostname        string
	port            int

	connReady     chan struct{}
	connReadyDone atomic.Bool

	isOpen atomic.Bool

	pendingMutex sync.Mutex
	pendingData  [][]byte
}

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

	srcKey := ""
	if c.srcIP != nil {
		srcKey = c.srcIP.String()
	}

	// Resolve to a single IP. Egress policy is applied to every candidate.
	resolvedIP := ""
	if ip := net.ParseIP(hostname); ip != nil {
		// IP literal: skip DNS but enforce egress.
		if ok, reason := egressEvaluate(c.globals, ip); !ok {
			c.repAddSource("privateEgress")
			c.repAddDest(ip.String(), s.port, "privateEgress")
			logEvent("egress_block", map[string]any{
				"srcIP": srcKey, "dstIP": ip.String(), "dstPort": s.port, "reason": reason,
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
			lastReason := ""
			for _, ip := range ips {
				ok, reason := egressEvaluate(c.globals, ip.IP)
				if ok {
					resolvedIP = ip.IP.String()
					break
				}
				lastReason = reason
			}
			if resolvedIP == "" {
				c.repAddSource("privateEgress")
				logEvent("egress_block", map[string]any{
					"srcIP": srcKey, "host": hostname, "dstPort": s.port, "reason": lastReason,
				})
				s.close(closeReasonBlocked)
				return
			}
		} else {
			resolvedIP = hostname
		}
	} else {
		resolvedIP = hostname
	}

	dstKey := net.JoinHostPort(resolvedIP, port)

	// Per-destination rate limits.
	if c.globals != nil {
		if c.globals.PerDestSec != nil && !c.globals.PerDestSec.Allow(dstKey) {
			c.violation("per_dest_sec")
			c.repAddSource("burstRate")
			c.repAddDest(resolvedIP, s.port, "burstRate")
			logEvent("flood_block", map[string]any{
				"srcIP": srcKey, "dstIP": resolvedIP, "dstPort": s.port,
				"streamId": s.streamId, "reason": "per_dest_sec",
			})
			s.close(closeReasonThrottled)
			return
		}
		if c.globals.PerDestMin != nil && !c.globals.PerDestMin.Allow(dstKey) {
			c.violation("per_dest_min")
			logEvent("flood_block", map[string]any{
				"srcIP": srcKey, "dstIP": resolvedIP, "dstPort": s.port,
				"streamId": s.streamId, "reason": "per_dest_min",
			})
			s.close(closeReasonThrottled)
			return
		}
	}

	// Reputation-strict destination check: if the destination is already
	// flagged as strict (lots of distinct sources / SYN signatures), refuse
	// and softly bump the requesting source.
	if c.globals != nil && c.globals.Reputation != nil {
		ds := c.globals.Reputation.DestScore(resolvedIP, s.port)
		if c.globals.Reputation.Tier(ds) == TierStrict {
			c.repAddSource("requestKnownBadDest")
			logEvent("flood_block", map[string]any{
				"srcIP": srcKey, "dstIP": resolvedIP, "dstPort": s.port,
				"streamId": s.streamId, "reason": "dest_reputation_strict",
			})
			s.close(closeReasonBlocked)
			return
		}
	}

	// In-flight SYN cap: hold for the lifetime of the dial only.
	synAcquired := false
	if c.globals != nil && c.globals.InFlightSyns != nil && streamType == streamTypeTCP {
		if !c.globals.InFlightSyns.TryAcquire() {
			c.violation("in_flight_syns")
			logEvent("flood_block", map[string]any{
				"srcIP": srcKey, "dstIP": resolvedIP, "dstPort": s.port,
				"streamId": s.streamId, "reason": "in_flight_syns",
			})
			s.close(closeReasonThrottled)
			return
		}
		synAcquired = true
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
				if synAcquired {
					c.globals.InFlightSyns.Release()
				}
				s.close(closeReasonNetworkError)
				return
			}
			s.conn, err = dialer.Dial("tcp", destination)
		} else {
			s.conn, err = cfg.Dialer.Dial("tcp", destination)
		}
	case streamTypeUDP:
		if cfg.DisableUDP || cfg.Proxy != "" {
			if synAcquired {
				c.globals.InFlightSyns.Release()
			}
			s.close(closeReasonBlocked)
			return
		}
		s.conn, err = net.Dial("udp", destination)
	default:
		if synAcquired {
			c.globals.InFlightSyns.Release()
		}
		s.close(closeReasonInvalidInfo)
		return
	}

	if synAcquired {
		c.globals.InFlightSyns.Release()
	}

	// Record dial outcome and check SYN-flood signature.
	if c.globals != nil && c.globals.Signature != nil && streamType == streamTypeTCP {
		det := c.globals.Signature.For(c.connID, resolvedIP, s.port)
		det.Record(err == nil)
		if det.Match() {
			c.repAddSource("synSignature")
			c.repAddDest(resolvedIP, s.port, "synSignature")
			logEvent("syn_signature", map[string]any{
				"srcIP": srcKey, "dstIP": resolvedIP, "dstPort": s.port, "streamId": s.streamId,
			})
			if err == nil && s.conn != nil {
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

// egressEvaluate is a nil-safe wrapper around EgressPolicy.Evaluate.
func egressEvaluate(g *Globals, ip net.IP) (bool, string) {
	if g == nil || g.Egress == nil {
		return true, ""
	}
	return g.Egress.Evaluate(ip)
}

func (s *wispStream) signalConnReady() {
	if s.connReadyDone.CompareAndSwap(false, true) {
		close(s.connReady)
	}
}

func (s *wispStream) readFromConnection() {
	const maxHeaderLen = 15
	bufp := s.wispConn.config.ReadBufPool.Get().(*[]byte)
	buf := *bufp
	defer s.wispConn.config.ReadBufPool.Put(bufp)

	streamId := s.streamId

	for {
		n, err := s.conn.Read(buf[maxHeaderLen:])
		if n > 0 {
			totalPayload := 5 + n
			var frameStart int

			if totalPayload <= 125 {
				frameStart = maxHeaderLen - 7
				buf[frameStart] = 0x82
				buf[frameStart+1] = byte(totalPayload)
			} else if totalPayload <= 65535 {
				frameStart = maxHeaderLen - 9
				buf[frameStart] = 0x82
				buf[frameStart+1] = 126
				buf[frameStart+2] = byte(totalPayload >> 8)
				buf[frameStart+3] = byte(totalPayload)
			} else {
				frameStart = 0
				buf[0] = 0x82
				buf[1] = 127
				buf[2] = 0
				buf[3] = 0
				buf[4] = 0
				buf[5] = 0
				buf[6] = byte(totalPayload >> 24)
				buf[7] = byte(totalPayload >> 16)
				buf[8] = byte(totalPayload >> 8)
				buf[9] = byte(totalPayload)
			}

			wispStart := maxHeaderLen - 5
			buf[wispStart] = packetTypeData
			buf[wispStart+1] = byte(streamId)
			buf[wispStart+2] = byte(streamId >> 8)
			buf[wispStart+3] = byte(streamId >> 16)
			buf[wispStart+4] = byte(streamId >> 24)

			frame := make([]byte, maxHeaderLen+n-frameStart)
			copy(frame, buf[frameStart:maxHeaderLen+n])
			s.wispConn.queueWrite(frame)
		}
		if err != nil {
			if err == io.EOF {
				s.close(closeReasonVoluntary)
			} else {
				s.close(closeReasonNetworkError)
			}
			return
		}
	}
}

func (s *wispStream) close(reason uint8) {
	if !s.isOpen.CompareAndSwap(true, false) {
		return
	}

	s.signalConnReady()

	s.wispConn.deleteWispStream(s.streamId)

	if s.conn != nil {
		s.conn.Close()
	}

	s.wispConn.sendClosePacket(s.streamId, reason)
}

func mapDialError(err error) uint8 {
	if err == nil {
		return closeReasonUnspecified
	}

	errStr := err.Error()

	if strings.Contains(errStr, "connection refused") {
		return closeReasonConnectionRefused
	}
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "no address") {
		return closeReasonUnreachable
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return closeReasonTimeout
	}
	if strings.Contains(errStr, "network is unreachable") || strings.Contains(errStr, "host is unreachable") {
		return closeReasonUnreachable
	}

	return closeReasonNetworkError
}
