package accesslog

import "sync"

// Ring is a bounded in-memory buffer of recent access entries, kept so the
// console can query recent traffic even when the full pipeline only ships
// off-host. Capacity-bounded (default 5000), lock-protected, dropped on
// restart — this is a live tail, not durable storage.
type Ring struct {
	mu   sync.Mutex
	buf  []Entry
	next int
	full bool
}

// NewRing creates a buffer holding the most recent cap entries.
func NewRing(cap int) *Ring {
	if cap <= 0 {
		cap = 5000
	}
	return &Ring{buf: make([]Entry, cap)}
}

// Write implements Sink: appends an entry, overwriting the oldest.
func (r *Ring) Write(e *Entry) {
	if e == nil {
		return
	}
	r.mu.Lock()
	r.buf[r.next] = *e
	r.next++
	if r.next >= len(r.buf) {
		r.next = 0
		r.full = true
	}
	r.mu.Unlock()
}

// Close implements Sink (no-op for an in-memory buffer).
func (r *Ring) Close() error { return nil }

// Recent returns up to limit newest entries (newest first), filtered by the
// optional substring matchers (site, q matches path/ua/rule/ip).
func (r *Ring) Recent(limit int, site, q, outcome string) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.buf)
	if !r.full {
		n = r.next
	}
	out := make([]Entry, 0, min(limit, n))
	// newest-first walk over the ring
	for i := 0; i < n && len(out) < limit; i++ {
		idx := (r.next - 1 - i + len(r.buf)) % len(r.buf)
		e := r.buf[idx]
		if site != "" && !containsFold(e.Site, site) {
			continue
		}
		if outcome != "" && e.Outcome != outcome {
			continue
		}
		if q != "" && !containsFold(e.Path, q) && !containsFold(e.UserAgent, q) &&
			!containsFold(e.ClientIP, q) && !containsFold(e.Rule, q) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Count returns the number of buffered entries.
func (r *Ring) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.full {
		return len(r.buf)
	}
	return r.next
}

func containsFold(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	// small buffers: simple case-insensitive scan without allocations
	n := len(s) - len(sub)
	for i := 0; i <= n; i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if 'A' <= a && a <= 'Z' {
				a += 32
			}
			if 'A' <= b && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Tee fans one entry out to two sinks (e.g. the console ring tail and the
// external shipper) without either blocking the other's accounting.
type Tee struct {
	first, second Sink
}

// NewTee wires two sinks in sequence.
func NewTee(first, second Sink) *Tee { return &Tee{first: first, second: second} }

// Write implements Sink.
func (t *Tee) Write(e *Entry) {
	if e == nil {
		return
	}
	t.first.Write(e)
	t.second.Write(e)
}

// Close implements Sink (closes the second sink; the ring needs no close).
func (t *Tee) Close() error { return t.second.Close() }

// Dropped proxies the shipper drop counter for metrics (0 when absent).
func (t *Tee) Dropped() int64 {
	if s, ok := t.second.(*Shipper); ok {
		return s.Dropped()
	}
	return 0
}

// Depth proxies the shipper queue depth for metrics (0 when absent).
func (t *Tee) Depth() int {
	if s, ok := t.second.(*Shipper); ok {
		return s.Depth()
	}
	return 0
}
