package proxy

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

func TestLogSamplerBurstAndSustain(t *testing.T) {
	s := newLogSampler(5)
	// First 5 messages in the window pass...
	granted := 0
	for i := 0; i < 5; i++ {
		if s.Allow() {
			granted++
		}
	}
	if granted != 5 {
		t.Fatalf("first 5 of window should pass, got %d", granted)
	}
	// ...the rest of the window is throttled, but not entirely silent.
	passed := 0
	for i := 0; i < 100; i++ {
		if s.Allow() {
			passed++
		}
	}
	if passed == 0 {
		t.Fatal("storm: sampler must keep 1-in-10 trace messages flowing")
	}
	if passed > 15 {
		t.Fatalf("storm: sampler leaked %d messages, expected <=~15", passed)
	}
}

func TestLogSamplerDisabledAndNil(t *testing.T) {
	// negative limit disables sampling entirely
	s := newLogSampler(-1)
	for i := 0; i < 1000; i++ {
		if !s.Allow() {
			t.Fatal("disabled sampler denied a message")
		}
	}
	var nilSampler *logSampler
	if !nilSampler.Allow() {
		t.Fatal("nil sampler should allow everything")
	}
}

func TestLimitedListenerCap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := newLimitedListener(ln, 1)

	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := limited.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()

	// First connection passes the cap.
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer c1.Close()
	var s1 net.Conn
	select {
	case s1 = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("first connection not accepted")
	}

	// Second connection is at capacity: accepted then immediately closed —
	// the client sees EOF/reset on read.
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	br := bufio.NewReader(c2)
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("over-cap connection should see EOF, got %v", err)
	}
	c2.Close()

	// Releasing the first connection frees the slot.
	s1.Close()
	c3, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 3: %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("third connection not accepted after release")
	}
	c3.Close()
}
