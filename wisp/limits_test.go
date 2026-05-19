package wisp

import (
	"sync"
	"sync/atomic"
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
	if !w.Allow("k2") {
		t.Fatal("key2 should be allowed independently")
	}
}

func TestSlidingWindowRollover(t *testing.T) {
	w := NewSlidingWindow(2, 50*time.Millisecond)
	w.Allow("k")
	w.Allow("k")
	if w.Allow("k") {
		t.Fatal("should be denied within window")
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
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if w.Allow("k") {
					atomic.AddInt64(&allowed, 1)
				}
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt64(&allowed); got != 100 {
		t.Fatalf("expected exactly 100 allowed, got %d", got)
	}
}

func TestSlidingWindowNilIsAllowAll(t *testing.T) {
	var w *SlidingWindow
	for i := 0; i < 1000; i++ {
		if !w.Allow("x") {
			t.Fatal("nil limiter must allow everything")
		}
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

func TestSemaphoreNilIsAllowAll(t *testing.T) {
	var s *Semaphore
	for i := 0; i < 100; i++ {
		if !s.TryAcquire() {
			t.Fatal("nil semaphore must allow everything")
		}
		s.Release()
	}
}
