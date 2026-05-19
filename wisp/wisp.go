package wisp

import (
	"crypto/ed25519"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxzan/gws"
)

type Config struct {
	DisableUDP bool

	TcpBufferSize         int
	BufferRemainingLength uint32
	TcpNoDelay            bool
	WebsocketTcpNoDelay   bool

	Blacklist struct {
		Hostnames map[string]struct{}
		Ports     map[string]struct{}
	}
	Whitelist struct {
		Hostnames map[string]struct{}
		Ports     map[string]struct{}
	}

	Proxy                      string
	WebsocketPermessageDeflate bool

	DnsServers []string

	EnableTwisp bool

	EnableV2             bool
	Motd                 string
	PasswordAuth         bool
	PasswordAuthRequired bool
	PasswordUsers        map[string]string
	CertAuth             bool
	CertAuthRequired     bool
	CertAuthPublicKeys   []ed25519.PublicKey
	EnableStreamConfirm  bool
	MaxConnectsPerSecond int

	MaxPayloadBytes int

	TrustedProxies []*net.IPNet
	TrustedHeaders []string

	Egress          *EgressPolicy
	FloodProtection *FloodProtectionConfig
	Reputation      *ReputationConfig
	Globals         *Globals

	DNSCache    *DNSCache
	ReadBufPool sync.Pool
	Dialer      net.Dialer
}

func DefaultConfig() *Config {
	return &Config{
		DisableUDP:            false,
		TcpBufferSize:         32768,
		BufferRemainingLength: 65536,
		TcpNoDelay:            true,
		WebsocketTcpNoDelay:   true,
		PasswordUsers:         make(map[string]string),
		MaxPayloadBytes:       1 << 20,
	}
}

func (c *Config) InitResolver() {
	c.DNSCache = NewDNSCache(c.DnsServers)
}

// FloodProtectionConfig groups every flood-mitigation knob.
type FloodProtectionConfig struct {
	Enabled                           bool
	MaxConnectsPerSourceIPPerSecond   int
	MaxConnectsPerDestPerSecond       int
	MaxConnectsPerDestPerMinute       int
	MaxInFlightSyns                   int
	MaxConcurrentStreamsPerConnection int
	MaxConcurrentConnections          int
	SynFloodSignature                 struct {
		Enabled              bool
		WindowMs             int
		MinSamples           int
		FailedHandshakeRatio float64
	}
	WsCloseAfterViolations int
	LogBlockedDials        bool
}

// BuildGlobals constructs the process-wide enforcement state from c.
// Idempotent: a non-nil c.Globals is left as-is.
func (c *Config) BuildGlobals() {
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

type upgradeHandler struct {
	gws.BuiltinEventHandler
}

func CreateWispHandler(config *Config) http.HandlerFunc {
	if config.WebsocketPermessageDeflate {
		panic("websocketPermessageDeflate is not supported by the hand-rolled WS reader; set it to false")
	}
	if config.MaxPayloadBytes <= 0 {
		config.MaxPayloadBytes = 1 << 20
	}

	config.InitResolver()
	config.BuildGlobals()

	readBufSize := 15 + config.TcpBufferSize
	config.ReadBufPool = sync.Pool{
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
			if config.WebsocketTcpNoDelay {
				tc.SetNoDelay(true)
			}
			tc.SetReadBuffer(1 << 20)
			tc.SetWriteBuffer(1 << 20)
		}

		srcIP := ResolveClientIP(r, config.TrustedProxies, config.TrustedHeaders)

		wc := &wispConnection{
			netConn:        netConn,
			writeCh:        make(chan writeReq, 4096), // funny number
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
}
