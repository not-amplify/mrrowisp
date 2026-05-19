package wisp

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// referenceMaskXOR is a simple byte-by-byte reference implementation.
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
	// Force unaligned access by slicing into a backing array at offset 1.
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
	cfg := DefaultConfig()
	cfg.MaxPayloadBytes = 1024 // tiny cap for the test
	cfg.InitResolver()
	// Initialize the read-buffer pool so the reader can run.
	cfg.ReadBufPool.New = func() any {
		buf := make([]byte, 32768)
		return &buf
	}

	// Build a single WS frame with payloadLen = 2 MiB. The reader must abort
	// before allocating the payload.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	wc := &wispConnection{
		netConn:      a,
		writeCh:      make(chan writeReq, 4),
		config:       cfg,
		twispStreams: newTwisp(),
	}
	wc.handshakeDone = nil

	done := make(chan struct{})
	go func() {
		wc.readLoop()
		close(done)
	}()

	// Frame: FIN=1 opcode=2 (binary), masked=1, lenCode=127, ext64 = 2*1024*1024
	header := []byte{0x82, 0x80 | 127, 0, 0, 0, 0, 0, 0x20, 0x00, 0x00}
	mask := []byte{1, 2, 3, 4}
	if _, err := b.Write(append(header, mask...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Do not write the payload. readLoop must give up promptly.

	select {
	case <-done:
		// Drain any frames written back (not required to be empty).
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not abort on oversized frame")
	}
}
