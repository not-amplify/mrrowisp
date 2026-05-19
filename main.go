package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"mrrowisp/wisp"
)

type FloodSig struct {
	Enabled              bool    `json:"enabled"`
	WindowMs             int     `json:"windowMs"`
	MinSamples           int     `json:"minSamples"`
	FailedHandshakeRatio float64 `json:"failedHandshakeRatio"`
}

type FloodCfg struct {
	Enabled                           bool     `json:"enabled"`
	MaxConnectsPerSourceIPPerSecond   int      `json:"maxConnectsPerSourceIPPerSecond"`
	MaxConnectsPerDestPerSecond       int      `json:"maxConnectsPerDestPerSecond"`
	MaxConnectsPerDestPerMinute       int      `json:"maxConnectsPerDestPerMinute"`
	MaxInFlightSyns                   int      `json:"maxInFlightSyns"`
	MaxConcurrentStreamsPerConnection int      `json:"maxConcurrentStreamsPerConnection"`
	MaxConcurrentConnections          int      `json:"maxConcurrentConnections"`
	SynFloodSignature                 FloodSig `json:"synFloodSignature"`
	WsCloseAfterViolations            int      `json:"wsCloseAfterViolations"`
	LogBlockedDials                   bool     `json:"logBlockedDials"`
}

type ReputationCfg struct {
	Enabled             bool `json:"enabled"`
	StorePath           string `json:"storePath"`
	SaveIntervalSeconds int    `json:"saveIntervalSeconds"`
	ScoreDecayPerHour   int    `json:"scoreDecayPerHour"`
	EvictAfterDays      int    `json:"evictAfterDays"`
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
	fp.SynFloodSignature = FloodSig{
		Enabled: true, WindowMs: 2000, MinSamples: 32, FailedHandshakeRatio: 0.75,
	}
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

func parseCIDRsOrIPs(items []string) []*net.IPNet {
	var out []*net.IPNet
	for _, t := range items {
		if !strings.Contains(t, "/") {
			if ip := net.ParseIP(t); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				t = fmt.Sprintf("%s/%d", t, bits)
			}
		}
		if _, n, err := net.ParseCIDR(t); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func createWispConfig(cfg Config) *wisp.Config {
	blacklistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Blacklist.Hostnames {
		blacklistedHostnames[host] = struct{}{}
	}
	blacklistedPorts := make(map[string]struct{})
	for _, port := range cfg.Blacklist.Ports {
		blacklistedPorts[fmt.Sprintf("%d", port)] = struct{}{}
	}

	whitelistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Whitelist.Hostnames {
		whitelistedHostnames[host] = struct{}{}
	}
	whitelistedPorts := make(map[string]struct{})
	for _, port := range cfg.Whitelist.Ports {
		whitelistedPorts[fmt.Sprintf("%d", port)] = struct{}{}
	}

	var pubKeys []ed25519.PublicKey
	for _, hexKey := range cfg.CertAuthPublicKeys {
		hexKeyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			fmt.Printf("warning: invalid public key hex %q: %v\n", hexKey, err)
			continue
		}
		if len(hexKeyBytes) != ed25519.PublicKeySize {
			fmt.Printf("warning: public key %q has invalid length %d (expected %d)\n", hexKey, len(hexKeyBytes), ed25519.PublicKeySize)
			continue
		}
		pubKeys = append(pubKeys, ed25519.PublicKey(hexKeyBytes))
	}

	dns := cfg.DnsServers
	if len(dns) == 0 && len(cfg.DnsServerLegacy) > 0 {
		fmt.Fprintln(os.Stderr, "warning: 'dnsServer' is deprecated; rename to 'dnsServers'")
		dns = cfg.DnsServerLegacy
	}

	wispCfg := &wisp.Config{
		DisableUDP:            cfg.DisableUDP,
		TcpBufferSize:         cfg.TcpBufferSize,
		BufferRemainingLength: cfg.BufferRemainingLength,
		TcpNoDelay:            cfg.TcpNoDelay,
		WebsocketTcpNoDelay:   cfg.WebsocketTcpNoDelay,
		Blacklist: struct {
			Hostnames map[string]struct{}
			Ports     map[string]struct{}
		}{
			Hostnames: blacklistedHostnames,
			Ports:     blacklistedPorts,
		},
		Whitelist: struct {
			Hostnames map[string]struct{}
			Ports     map[string]struct{}
		}{
			Hostnames: whitelistedHostnames,
			Ports:     whitelistedPorts,
		},
		Proxy:                      cfg.Proxy,
		WebsocketPermessageDeflate: cfg.WebsocketPermessageDeflate,
		DnsServers:                 dns,
		EnableTwisp:                cfg.EnableTwisp,
		EnableV2:                   cfg.EnableV2,
		Motd:                       cfg.Motd,
		PasswordAuth:               cfg.PasswordAuth,
		PasswordAuthRequired:       cfg.PasswordAuthRequired,
		PasswordUsers:              cfg.PasswordUsers,
		CertAuth:                   cfg.CertAuth,
		CertAuthRequired:           cfg.CertAuthRequired,
		CertAuthPublicKeys:         pubKeys,
		EnableStreamConfirm:        cfg.EnableStreamConfirm,
		MaxConnectsPerSecond:       cfg.MaxConnectsPerSecond,
		MaxPayloadBytes:            cfg.MaxPayloadBytes,
		TrustedProxies:             parseCIDRsOrIPs(cfg.TrustedProxies),
		TrustedHeaders:             cfg.TrustedHeaders,
	}

	if wispCfg.PasswordUsers == nil {
		wispCfg.PasswordUsers = make(map[string]string)
	}

	if cfg.FloodProtection != nil {
		fp := *cfg.FloodProtection
		wfp := &wisp.FloodProtectionConfig{
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
		wfp.SynFloodSignature.Enabled = fp.SynFloodSignature.Enabled
		wfp.SynFloodSignature.WindowMs = fp.SynFloodSignature.WindowMs
		wfp.SynFloodSignature.MinSamples = fp.SynFloodSignature.MinSamples
		wfp.SynFloodSignature.FailedHandshakeRatio = fp.SynFloodSignature.FailedHandshakeRatio
		wispCfg.FloodProtection = wfp
	}

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
		wispCfg.Reputation = &rc
	}

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
		e.AllowCIDRs = parseCIDRsOrIPs(cfg.Egress.AllowCIDRs)
		e.DenyCIDRs = parseCIDRsOrIPs(cfg.Egress.DenyCIDRs)
		wispCfg.Egress = &e
	}

	return wispCfg
}

func main() {
	fConfig := flag.String("config", "", "config to load (file path; passing JSON on the command line is deprecated)")
	fPort := flag.Int("port", 0, "port to run on")
	flag.Parse()

	var cfg Config
	var err error

	if *fConfig != "" {
		cfg, err = loadConfig(*fConfig)
		if err != nil {
			fmt.Printf("Failed to load config: %v\n", err)
			return
		}
	} else {
		cfg = defaultConfig()
	}

	if *fPort != 0 {
		cfg.Port = *fPort
	}

	wispConfig := createWispConfig(cfg)
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

	stop := make(chan struct{})
	if wispConfig.Globals != nil && wispConfig.Globals.Reputation != nil && cfg.Reputation != nil {
		saveEvery := time.Duration(cfg.Reputation.SaveIntervalSeconds) * time.Second
		if saveEvery <= 0 {
			saveEvery = 30 * time.Second
		}
		go wispConfig.Globals.Reputation.RunMaintenance(stop, saveEvery)
	}

	fmt.Printf("Starting Mrrowisp on port %d. . .\n", cfg.Port)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("Failed to start Mrrowisp: %v\n", err)
	}
	close(stop)
}
