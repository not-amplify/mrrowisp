package wisp

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReputationAddAndScore(t *testing.T) {
	r := NewReputation(ReputationConfig{
		Enabled: true,
		Weights: map[string]int{"foo": 10},
	})
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
	r := NewReputation(ReputationConfig{
		Enabled: true,
		Weights: map[string]int{"big": 60},
	})
	r.AddSource("a", "big")
	r.AddSource("a", "big")
	if r.SourceScore("a") != 100 {
		t.Fatalf("expected clamp to 100, got %d", r.SourceScore("a"))
	}
}

func TestReputationDestDistinctSources(t *testing.T) {
	r := NewReputation(ReputationConfig{
		Enabled: true,
		DestWeights: map[string]int{
			"hit":                       1,
			"distinctSourcesEscalation": 1,
		},
	})
	for i := 0; i < 50; i++ {
		r.AddDest("9.9.9.9", 80, "hit", net.ParseIP(fmt.Sprintf("10.0.0.%d", i+1)))
	}
	if got := r.DestScore("9.9.9.9", 80); got < 50 {
		t.Fatalf("expected score >= 50, got %d", got)
	}
}

func TestReputationPersistRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rep.json")
	r := NewReputation(ReputationConfig{
		Enabled:   true,
		Weights:   map[string]int{"x": 7},
		StorePath: path,
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
		Enabled:   true,
		Weights:   map[string]int{"x": 7},
		StorePath: path,
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
		Enabled:      true,
		Weights:      map[string]int{"x": 50},
		DecayPerHour: 50,
	})
	r.AddSource("a", "x")
	r.ForceDecay(time.Hour)
	if got := r.SourceScore("a"); got != 0 {
		t.Fatalf("expected 0 after decay, got %d", got)
	}
}

func TestReputationTier(t *testing.T) {
	cfg := ReputationConfig{Enabled: true}
	cfg.Thresholds.Warn = 20
	cfg.Thresholds.Throttle = 50
	cfg.Thresholds.Strict = 80
	r := NewReputation(cfg)
	cases := []struct {
		score int
		want  Tier
	}{
		{0, TierNormal}, {19, TierNormal},
		{20, TierWarn}, {49, TierWarn},
		{50, TierThrottle}, {79, TierThrottle},
		{80, TierStrict}, {100, TierStrict},
	}
	for _, c := range cases {
		if got := r.Tier(c.score); got != c.want {
			t.Errorf("score=%d got=%v want=%v", c.score, got, c.want)
		}
	}
}

func TestReputationNilSafe(t *testing.T) {
	var r *Reputation
	r.AddSource("x", "y")
	r.AddDest("a", 1, "b", net.IPv4zero)
	if r.SourceScore("x") != 0 {
		t.Fatal("expected 0 from nil")
	}
	if r.Tier(50) != TierNormal {
		t.Fatal("nil Tier should be Normal")
	}
}
