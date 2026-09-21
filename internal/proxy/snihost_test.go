package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// sniSeen is a concurrency-safe record of the TLS ServerName each request
// carried (path=sni), as seen by the test server.
type sniSeen struct {
	mu    sync.Mutex
	notes []string
}

func (s *sniSeen) add(path, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notes = append(s.notes, path+"="+name)
}

func (s *sniSeen) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.notes...)
}

// startSNITestServer starts an HTTPS test server whose self-signed
// certificate carries CN/SAN = aihub.genomics.cn and records the TLS
// ServerName (the SNI the client actually sent) of every request.
func startSNITestServer(t *testing.T) (addr string, seen *sniSeen, conns *atomic.Int64, closeFn func()) {
	t.Helper()
	certPEM, keyPEM := genSelfSigned(t, "aihub.genomics.cn")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	seen = &sniSeen{}
	var connCount atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.add(r.URL.Path, r.TLS.ServerName)
		io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			connCount.Add(1)
		}
	}
	srv.StartTLS()
	return srv.Listener.Addr().String(), seen, &connCount, srv.Close
}

// TestSNIHostDialPinsServerName: with upstream sni_host set, a request whose
// URL host is 127.0.0.1 must reach the upstream with the pinned SNI — even
// when the request context carries a client SNI (sni_host is connection-level
// config and must never be overridden per-request).
func TestSNIHostDialPinsServerName(t *testing.T) {
	addr, seen, _, closeFn := startSNITestServer(t)
	defer closeFn()

	tr := newUpstreamTransport(config.Upstream{SNIHost: "aihub.genomics.cn"})
	cli := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	ctx := context.WithValue(context.Background(), clientSNIKey{}, "client.example.com")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/one", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("GET https://%s/one: %v", addr, err)
	}
	resp.Body.Close()

	got := seen.all()
	if len(got) != 1 || !strings.HasSuffix(got[0], "=aihub.genomics.cn") {
		t.Fatalf("server saw %v, want path=aihub.genomics.cn (request URL host %s)", got, addr)
	}
}

// TestSNIHostDialReuseAcrossHosts is the defect regression: two requests for
// different Hosts/paths riding the SAME keep-alive TLS connection must both
// carry the pinned SNI. Before the fix, a sni_forward-style per-request SNI
// would mismatch on the reused connection.
func TestSNIHostDialReuseAcrossHosts(t *testing.T) {
	addr, seen, conns, closeFn := startSNITestServer(t)
	defer closeFn()

	tr := newUpstreamTransport(config.Upstream{SNIHost: "aihub.genomics.cn"})
	cli := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	get := func(host, path string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "https://"+addr+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Host = host
		resp, err := cli.Do(req)
		if err != nil {
			t.Fatalf("GET %s%s: %v", host, path, err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if resp.StatusCode != http.StatusOK || string(b) != "ok" {
			t.Fatalf("GET %s%s: status=%d body=%q", host, path, resp.StatusCode, b)
		}
	}
	get("a.example.com", "/one")
	get("b.example.com", "/two")

	got := seen.all()
	if len(got) != 2 {
		t.Fatalf("server saw %d requests, want 2: %v", len(got), got)
	}
	for _, s := range got {
		if !strings.HasSuffix(s, "=aihub.genomics.cn") {
			t.Fatalf("reused-connection SNI mismatch: %v (second request must keep the pinned sni_host)", got)
		}
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("upstream connections opened = %d, want 1 (requests must share one keep-alive TLS connection)", n)
	}
}

// TestSNIForwardDialUsesClientSNI is the sni_forward control group: the dial
// overrides the address host with the per-request client SNI from the
// context, and falls back to the address host without one.
func TestSNIForwardDialUsesClientSNI(t *testing.T) {
	addr, _, _, closeFn := startSNITestServer(t)
	defer closeFn()

	dial := sniForwardDial(false)
	ctx := context.WithValue(context.Background(), clientSNIKey{}, "client.example.com")

	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("sni_forward dial with client SNI: %v", err)
	}
	tc := conn.(*tls.Conn)
	if got := tc.ConnectionState().ServerName; got != "client.example.com" {
		t.Fatalf("sni_forward ServerName = %q, want client.example.com", got)
	}
	conn.Close()

	// 无客户端 SNI（HTTP hop）→ 回退 addr host；用 localhost:port 形式
	// 避免 IP 地址（Go TLS 对 IP 不发送 SNI 扩展，ConnectionState 为空）。
	_, port, _ := net.SplitHostPort(addr)
	conn2, err := dial(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("sni_forward dial without client SNI: %v", err)
	}
	tc2 := conn2.(*tls.Conn)
	if got := tc2.ConnectionState().ServerName; got != "localhost" {
		t.Fatalf("sni_forward fallback ServerName = %q, want localhost (address host)", got)
	}
	conn2.Close()
}
