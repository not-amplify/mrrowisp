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
		t.Fatal("below min samples should not match")
	}
}

func TestSignatureWindowExpiry(t *testing.T) {
	s := NewSignatures(SignatureConfig{
		Enabled:              true,
		Window:               50 * time.Millisecond,
		MinSamples:           4,
		FailedHandshakeRatio: 0.5,
	})
	d := s.For(1, "x", 1)
	for i := 0; i < 10; i++ {
		d.Record(false)
	}
	if !d.Match() {
		t.Fatal("should match before window expires")
	}
	time.Sleep(80 * time.Millisecond)
	d.Record(true) // forces a cleanup; old failures are gone
	if d.Match() {
		t.Fatal("old failures should have aged out")
	}
}

func TestSignatureDisabledIsNop(t *testing.T) {
	s := NewSignatures(SignatureConfig{Enabled: false})
	d := s.For(1, "x", 1)
	d.Record(false)
	if d.Match() {
		t.Fatal("disabled signatures should never match")
	}
}

func TestSignaturesForget(t *testing.T) {
	s := NewSignatures(SignatureConfig{
		Enabled:              true,
		Window:               time.Second,
		MinSamples:           1,
		FailedHandshakeRatio: 0.5,
	})
	d1 := s.For(1, "x", 1)
	d1.Record(false)
	s.Forget(1)
	d2 := s.For(1, "x", 1)
	if d2 == d1 {
		t.Fatal("Forget should evict the detector")
	}
}
