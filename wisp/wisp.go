package wisp

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxzan/gws"
)

const (
	defaultStreamLimitPerHost    = 512
	defaultStreamLimitTotal      = 16384
	defaultMaxConnectsPerSecond  = 20
	defaultConnectionsLimitPerIP = 120
	defaultHandshakeFailures     = 10
)

func (cfg *Config) InitResolver() {
	cfg.DNSCache = NewDNSCache(
		DNSCacheConfig{
			Servers:     cfg.DnsServers,
			Method:      cfg.DnsMethod,
			ResultOrder: cfg.DnsResultOrder,
		})
	cfg.Logger = newLogger(cfg.LogLevel)

	cfg.trustedProxyNets = cfg.trustedProxyNets[:0]
	for _, t := range cfg.TrustedProxies {
		entry := t
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				entry = fmt.Sprintf("%s/%d", entry, bits)
			}
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			cfg.trustedProxyNets = append(cfg.trustedProxyNets, n)
		}
	}
}

// BuildGlobals constructs the process-wide enforcement state from cfg.
// Idempotent: an already-built cfg.Globals is left as-is.
func (cfg *Config) BuildGlobals() {
	if cfg.Globals != nil {
		return
	}
	g := &Globals{Egress: PolicyFromConfig(cfg)}
	if cfg.FloodProtection != nil && cfg.FloodProtection.Enabled {
		fp := cfg.FloodProtection
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
	if cfg.Reputation != nil && cfg.Reputation.Enabled {
		rc := *cfg.Reputation
		if rc.EvictAfter == 0 && rc.EvictDays > 0 {
			rc.EvictAfter = time.Duration(rc.EvictDays) * 24 * time.Hour
		}
		g.Reputation = NewReputation(rc)
		_ = g.Reputation.Load()
	}
	cfg.Globals = g
}

type upgradeHandler struct {
	gws.BuiltinEventHandler
}

func CreateWispHandler(config *Config) http.HandlerFunc {
	config.InitResolver()
	config.BuildGlobals()

	readBufSize := 15 + config.TcpBufferSize
	config.ReadBufPool = &sync.Pool{
		New: func() any {
			buf := make([]byte, readBufSize)
			return &buf
		},
	}

	config.Dialer = net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	upgrader := gws.NewUpgrader(&upgradeHandler{}, &gws.ServerOption{
		PermessageDeflate: gws.PermessageDeflate{
			Enabled: false,
		},
	})

	return func(w http.ResponseWriter, r *http.Request) {
		// Cap concurrent WS connections before upgrade.
		if config.Globals != nil && config.Globals.Connections != nil {
			if !config.Globals.Connections.TryAcquire() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
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
			tc.SetReadBuffer(1 << 20)
			tc.SetWriteBuffer(1 << 20)
		}

		var trusted []*net.IPNet
		if config.ParseRealIP {
			trusted = config.trustedProxyNets
		}
		remoteIP := ResolveClientIP(r, trusted, config.TrustedHeaders)

		wc := &wispConnection{
			netConn:      netConn,
			writeCh:      make(chan writeReq, 4096), // funny number
			config:       config,
			twispStreams: newTwisp(),
			isV2:         useV2,
			remoteIP:     remoteIP.String(),
			globals:      config.Globals,
			connID:       atomic.AddUint64(&connIDCounter, 1),
		}

		go wc.writeLoop()

		if useV2 {
			go wc.v2Handshake()
		} else {
			wc.sendPacket(0, config.BufferRemainingLength)
			go wc.readLoop()
		}
	}
}

func (cfg *Config) requiresV2() bool {
	if cfg == nil {
		return false
	}
	return cfg.PasswordAuthRequired || cfg.EnableTwisp
}
