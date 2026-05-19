package wisp

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ReputationConfig configures the reputation store.
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

// SourceEntry tracks reputation for a single source IP.
type SourceEntry struct {
	Score     int            `json:"score"`
	FirstSeen time.Time      `json:"firstSeen"`
	LastSeen  time.Time      `json:"lastSeen"`
	Events    map[string]int `json:"events"`
}

// DestEntry tracks reputation for a single destination IP:port. It records
// the set of distinct source IPs that have hit it so we can detect
// botnet-style distributed abuse.
type DestEntry struct {
	Score           int             `json:"score"`
	FirstSeen       time.Time       `json:"firstSeen"`
	LastSeen        time.Time       `json:"lastSeen"`
	Events          map[string]int  `json:"events"`
	DistinctSources int             `json:"distinctSources"`
	SeenSources     map[string]bool `json:"seenSources"`
}

// Reputation is the in-memory store. Methods are nil-safe.
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

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// AddSource bumps the source entry's score by the configured weight for
// reason and records the event. No-op for nil receiver.
func (r *Reputation) AddSource(key, reason string) {
	if r == nil {
		return
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
	if e.Events == nil {
		e.Events = make(map[string]int)
	}
	e.Events[reason]++
	e.Score = clampScore(e.Score + w)
}

// AddDest bumps the destination entry's score by the configured destination
// weight for reason. When srcIP is new for this destination, the
// destination's score also gets the distinctSourcesEscalation bonus.
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
	if e.Events == nil {
		e.Events = make(map[string]int)
	}
	if e.SeenSources == nil {
		e.SeenSources = make(map[string]bool)
	}
	e.Events[reason]++
	e.Score = clampScore(e.Score + w)
	if srcIP != nil {
		s := srcIP.String()
		if !e.SeenSources[s] {
			e.SeenSources[s] = true
			e.DistinctSources++
			if esc := r.cfg.DestWeights["distinctSourcesEscalation"]; esc != 0 {
				e.Score = clampScore(e.Score + esc)
			}
		}
	}
}

// SourceScore returns the current score for key, 0 if unknown.
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

// DestScore returns the current score for the destination, 0 if unknown.
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

// Tier maps a score to a configured tier.
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
	case t.Strict > 0 && score >= t.Strict:
		return TierStrict
	case t.Throttle > 0 && score >= t.Throttle:
		return TierThrottle
	case t.Warn > 0 && score >= t.Warn:
		return TierWarn
	}
	return TierNormal
}

type repSnapshot struct {
	Sources map[string]*SourceEntry `json:"sources"`
	Dests   map[string]*DestEntry   `json:"destinations"`
}

// SaveNow writes the current store to StorePath via atomic rename.
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

// Load reads the store from StorePath. A missing file is not an error.
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

// ForceDecay subtracts DecayPerHour * (elapsed / hour) from every entry's
// score, clamped to 0. Exposed for tests; production code uses a goroutine.
func (r *Reputation) ForceDecay(elapsed time.Duration) {
	if r == nil || r.cfg.DecayPerHour == 0 {
		return
	}
	delta := int(float64(r.cfg.DecayPerHour) * elapsed.Hours())
	if delta <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.sources {
		e.Score = clampScore(e.Score - delta)
	}
	for _, e := range r.dests {
		e.Score = clampScore(e.Score - delta)
	}
	r.lastDecay = time.Now()
}

// Evict removes entries whose score is below 5 and whose LastSeen is older
// than EvictAfter. No-op if EvictAfter is zero.
func (r *Reputation) Evict() {
	if r == nil || r.cfg.EvictAfter == 0 {
		return
	}
	cutoff := time.Now().Add(-r.cfg.EvictAfter)
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, e := range r.sources {
		if e.Score < 5 && e.LastSeen.Before(cutoff) {
			delete(r.sources, k)
		}
	}
	for k, e := range r.dests {
		if e.Score < 5 && e.LastSeen.Before(cutoff) {
			delete(r.dests, k)
		}
	}
}

// RunMaintenance ticks every saveEvery, applying decay, eviction, and
// persistence. Exits when stop is closed; performs a final save on exit.
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
			r.Evict()
			_ = r.SaveNow()
		}
	}
}
