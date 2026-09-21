package botlib

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestMatchGoodBots(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":            "Googlebot",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)":             "bingbot",
		"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)": "Baiduspider",
		"Mozilla/5.0 (compatible; YandexBot/3.0)":                                             "YandexBot",
	}
	for ua, want := range cases {
		got := Match(ua)
		if got.Class != ClassGood || got.Name != want {
			t.Errorf("Match(%q) = %+v, want good/%s", ua, got, want)
		}
	}
}

func TestMatchBadBots(t *testing.T) {
	cases := map[string]string{
		"sqlmap/1.5#stable (http://sqlmap.org)": "sqlmap",
		"python-requests/2.28.0":                "python-requests",
		"curl/8.0.1":                            "curl",
		"Wget/1.21.2":                           "wget",
		"Go-http-client/2.0":                    "go-http-client",
		"okhttp/4.9.3":                          "okhttp",
		"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)": "nuclei",
		"": "empty-ua",
	}
	for ua, want := range cases {
		got := Match(ua)
		if got.Class != ClassBad || got.Name != want {
			t.Errorf("Match(%q) = %+v, want bad/%s", ua, got, want)
		}
	}
}

func TestMatchUnknown(t *testing.T) {
	got := Match("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	if got.Class != ClassUnknown {
		t.Errorf("browser UA classified %q, want unknown", got.Class)
	}
	got2 := Match("SomeOddClient/1.0")
	if got2.Class != ClassUnknown {
		t.Errorf("odd UA classified %q, want unknown", got2.Class)
	}
}

func TestRateCounter(t *testing.T) {
	rc := NewRateCounter(3, time.Minute)
	base := time.Now()
	rc.nowFunc = func() time.Time { return base }
	for i := 0; i < 3; i++ {
		if rc.Over("k1") {
			t.Fatalf("hit %d flagged over quota", i+1)
		}
	}
	if !rc.Over("k1") {
		t.Fatal("4th hit should be over quota")
	}
	if rc.Over("k2") {
		t.Fatal("unrelated key must not be affected")
	}

	rc.nowFunc = func() time.Time { return base.Add(2 * time.Minute) }
	if rc.Over("k1") {
		t.Fatal("window expiry should reset the counter")
	}
}

func TestFingerprintStable(t *testing.T) {
	ctx := context.Background()
	r1, _ := http.NewRequestWithContext(ctx, "GET", "http://x/", nil)
	r1.Header.Set("User-Agent", "ua-a")
	r1.Header.Set("Accept-Language", "zh-CN")
	r1.Header.Set("Accept", "text/html")

	r2 := r1.Clone(ctx)

	r3 := r1.Clone(ctx)
	r3.Header.Set("X-Random-Extra", "1")

	fp1, fp2 := Fingerprint("10.0.0.1", "ua-a", r1), Fingerprint("10.0.0.1", "ua-a", r2)
	if fp1 == "" || fp1 != fp2 {
		t.Fatalf("fingerprint not stable: %q vs %q", fp1, fp2)
	}
	if fp3 := Fingerprint("10.0.0.2", "ua-a", r1); fp3 == fp1 {
		t.Fatal("different IP must change the fingerprint")
	}
	if fp3 := Fingerprint("10.0.0.1", "ua-b", r3); fp3 == fp1 {
		t.Fatal("different UA must change the fingerprint")
	}
}
