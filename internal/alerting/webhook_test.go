package alerting

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

func TestWebhookDeliversEvents(t *testing.T) {
	var mu sync.Mutex
	var bodies []logstore.Event
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev logstore.Event
		_ = json.Unmarshal(b, &ev)
		mu.Lock()
		bodies = append(bodies, ev)
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	wh := NewWebhook(config.WebhookSettings{URL: ts.URL, TimeoutSec: 2}, nil)
	defer wh.Close()

	wh.Write(&logstore.Event{Action: "blocked", Rule: "acl/blacklist", Site: "t.local"})
	wh.Write(&logstore.Event{Action: "challenged", Rule: "captcha/slider", Site: "t.local"})

	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no webhook delivery within 5s")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no event delivered")
	}
}

func TestWebhookDropsUnderBackpressure(t *testing.T) {
	release := make(chan struct{})
	wh := newWebhook(config.WebhookSettings{URL: hangingServer(t, release), TimeoutSec: 1}, 4, nil)
	// Release the hanging server before Close drains the queue (LIFO).
	defer close(release)
	defer wh.Close()

	for i := 0; i < 20; i++ {
		wh.Write(&logstore.Event{Action: "blocked"})
	}
	if wh.Dropped() == 0 {
		t.Fatal("expected drops under backpressure")
	}
}

// hangingServer returns a URL whose handler blocks until release closes.
func hangingServer(t *testing.T, release chan struct{}) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}
