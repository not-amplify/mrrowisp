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
	// Drain the reader side so writeLoop doesn't block on Pipe writes.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()

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
	wc.deleteAllWispStreams() // closes writeCh and writeDone

	wg.Wait() // must not panic
}
