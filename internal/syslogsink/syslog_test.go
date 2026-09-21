package syslogsink

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

func testSettings(url string, sys *config.SyslogSettings) config.ShipperSettings {
	return config.ShipperSettings{Type: "syslog", URL: url, Index: "kingmoat", Syslog: sys}
}

func TestFormatMessageRFC5424(t *testing.T) {
	c, err := newClient(&config.SyslogSettings{
		Hostname: "waf-node-01",
		AppName:  "kingmoat",
	}, "tcp://syslog.example.com:514", "kingmoat", "kingmoat", time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	ts := time.Date(2026, 9, 16, 9, 30, 5, 123456000, time.FixedZone("CST", 8*3600))
	got := c.formatMessage(ts, "blocked", `{"action":"blocked"}`, 4)
	// PRI = 16*8+4 = 132
	want := "<132>1 2026-09-16T09:30:05.123456+08:00 waf-node-01 kingmoat - blocked - {\"action\":\"blocked\"}"
	if got != want {
		t.Fatalf("rfc5424 mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatMessageRFC3164(t *testing.T) {
	c, err := newClient(&config.SyslogSettings{
		Format:   "rfc3164",
		Hostname: "waf-node-01",
		AppName:  "kingmoat",
	}, "udp://127.0.0.1:5140", "kingmoat", "kingmoat", time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	ts := time.Date(2026, 9, 7, 9, 30, 5, 0, time.FixedZone("CST", 8*3600))
	got := c.formatMessage(ts, "blocked", "hello world", 0)
	// PRI = 16*8+6 = 134 (default severity 6); day is space-padded.
	if !strings.HasPrefix(got, "<134>Sep  7 09:30:05 waf-node-01 kingmoat: hello world") {
		t.Fatalf("rfc3164 mismatch: %s", got)
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		sys    *config.SyslogSettings
		wantOK bool
	}{
		{"missing url", "  ", nil, false},
		{"missing syslog settings", "udp://127.0.0.1:514", nil, false},
		{"bad protocol", "ws://127.0.0.1:514", &config.SyslogSettings{}, false},
		{"protocol override bad", "udp://127.0.0.1:514", &config.SyslogSettings{Protocol: "sctp"}, false},
		{"bad format", "udp://127.0.0.1:514", &config.SyslogSettings{Format: "json"}, false},
		{"bad framing", "tcp://127.0.0.1:514", &config.SyslogSettings{Framing: "raw"}, false},
		{"facility range", "udp://127.0.0.1:514", &config.SyslogSettings{Facility: 24}, false},
		{"severity range", "udp://127.0.0.1:514", &config.SyslogSettings{Severity: 8}, false},
		{"bare host ok", "10.0.0.8", &config.SyslogSettings{}, true},
		{"tls ok", "tls://collector:6514", &config.SyslogSettings{}, true},
	}
	for _, tc := range cases {
		_, err := newClient(tc.sys, tc.url, "kingmoat", "kingmoat", time.Second)
		if tc.wantOK && err != nil {
			t.Errorf("%s: expected ok, got error %v", tc.name, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

func TestSendUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	c, err := New(testSettings("udp://"+pc.LocalAddr().String(), &config.SyslogSettings{
		Hostname: "waf-node-01",
	}), "kingmoat")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	msg := `{"action":"blocked","rule":"coraza/rule-949110"}`
	if err := c.Send(time.Now(), "blocked", msg, 4); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 4096)
	if err := pc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "<132>1 ") {
		t.Fatalf("PRI/version prefix missing: %s", got)
	}
	if !strings.HasSuffix(got, msg) {
		t.Fatalf("message body missing: %s", got)
	}
	if !strings.Contains(got, " kingmoat ") {
		t.Fatalf("APP-NAME missing: %s", got)
	}
}

func TestSendTCPNewline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	type received struct {
		line string
	}
	ch := make(chan received, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sc := bufio.NewScanner(conn)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			ch <- received{line: sc.Text()}
		}
	}()

	c, err := New(testSettings("tcp://"+ln.Addr().String(), &config.SyslogSettings{
		Framing:  "newline",
		Hostname: "waf-node-01",
	}), "kingmoat")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first := `{"action":"monitor"}`
	second := `{"action":"blocked"}`
	if err := c.Send(time.Now(), "monitor", first, 0); err != nil {
		t.Fatalf("Send 1: %v", err)
	}
	if err := c.Send(time.Now(), "blocked", second, 4); err != nil {
		t.Fatalf("Send 2: %v", err)
	}

	for i, want := range []string{first, second} {
		select {
		case r := <-ch:
			if !strings.HasSuffix(r.line, want) {
				t.Fatalf("frame %d mismatch: %s", i, r.line)
			}
			if !strings.HasPrefix(r.line, "<") {
				t.Fatalf("frame %d missing PRI: %s", i, r.line)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("frame %d not received", i)
		}
	}
}

func TestSendTCPOctetFraming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	ch := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the octet-counted frame: "<digits> " prefix then N bytes.
		buf := make([]byte, 1)
		var digits []byte
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
			if buf[0] == ' ' {
				break
			}
			digits = append(digits, buf[0])
		}
		n := 0
		for _, d := range digits {
			n = n*10 + int(d-'0')
		}
		body := make([]byte, n)
		if _, err := readFull(conn, body); err != nil {
			return
		}
		ch <- string(body)
	}()

	c, err := New(testSettings("tcp://"+ln.Addr().String(), &config.SyslogSettings{
		Hostname: "waf-node-01",
	}), "kingmoat")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Send(time.Now(), "blocked", "payload-with spaces", 4); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-ch:
		if !strings.HasSuffix(got, "payload-with spaces") {
			t.Fatalf("frame mismatch: %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("frame not received")
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
