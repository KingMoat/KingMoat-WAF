package logstore

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestReadAndWriteConcurrency proves the split pools work under load: a
// heavy query loop cannot starve the audit writer (the pre-split behavior
// starved writes behind the single shared connection).
func TestReadAndWriteConcurrency(t *testing.T) {
	s, err := NewSQLiteStore(t.TempDir()+"/rw.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Writer: 3000 events in bursts (exceeds the 1024 queue, forces flushes).
	stopWrite := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			s.Write(&Event{
				TS:    time.Now().Format(time.RFC3339Nano),
				Site:  "a.local",
				Path:  fmt.Sprintf("/p/%d", i),
				Action: "monitor",
			})
			if i%100 == 0 {
				select {
				case <-stopWrite:
					return
				default:
				}
			}
		}
	}()

	// Reader: hammer the query path while writes are in flight.
	readDeadlines := 0
	for i := 0; i < 30; i++ {
		evs, err := s.Query(LogQuery{Site: "a.local", Limit: 50})
		if err != nil {
			// 5s timeout would surface here as an error
			readDeadlines++
			if readDeadlines > 2 {
				t.Fatalf("query path repeatedly starved: %v", err)
			}
		} else if len(evs) > 50 {
			t.Fatalf("query returned %d events, limit 50", len(evs))
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The writer must complete without starving.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		close(stopWrite)
		t.Fatal("writer starved by concurrent reads (read/write split failed)")
	}
	close(stopWrite)

	if err := s.Flush(5 * time.Second); err != nil {
		t.Fatalf("flush after concurrent load: %v", err)
	}
}
