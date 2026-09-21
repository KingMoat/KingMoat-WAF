// Package botlib provides the data-plane bot classification primitives:
// an embedded user-agent rule table, a stable client fingerprint and a
// sharded in-memory rate counter. It is a pure library with no runtime
// dependencies; everything compiles into the binary.
package botlib

import (
	"strings"
)

// Class is the tri-state bot classification.
type Class string

const (
	ClassGood    Class = "good"
	ClassUnknown Class = "unknown"
	ClassBad     Class = "bad"
)

// Result is the UA classification outcome.
type Result struct {
	Class      Class
	Name       string
	Confidence float64 // 0..1; UA is spoofable so the UI must surface it
}

// uaRule is one substring matcher (case-insensitive). Class good/bad rules
// also carry the well-known bot or tool name.
type uaRule struct {
	substr   string
	class    Class
	name     string
	conf     float64
	headOnly bool
}

// uaTable is the embedded classification table. Order matters: more specific
// rules first. good = legitimate crawlers (allow/bypass), bad = scripted
// clients and attack tooling, unknown = everything else.
var uaTable = []uaRule{
	// Attack tooling first — these must never be classified good.
	{substr: "sqlmap", class: ClassBad, name: "sqlmap", conf: 0.99},
	{substr: "nuclei", class: ClassBad, name: "nuclei", conf: 0.99},
	{substr: "xray", class: ClassBad, name: "xray", conf: 0.95},
	{substr: "masscan", class: ClassBad, name: "masscan", conf: 0.99},
	{substr: "zgrab", class: ClassBad, name: "zgrab", conf: 0.99},
	{substr: "nikto", class: ClassBad, name: "nikto", conf: 0.99},
	{substr: "dirbuster", class: ClassBad, name: "dirbuster", conf: 0.95},
	{substr: "gobuster", class: ClassBad, name: "gobuster", conf: 0.95},
	{substr: "ffuf", class: ClassBad, name: "ffuf", conf: 0.95},
	{substr: "nmap", class: ClassBad, name: "nmap", conf: 0.95},
	{substr: "acunetix", class: ClassBad, name: "acunetix", conf: 0.95},
	{substr: "nessus", class: ClassBad, name: "nessus", conf: 0.95},
	{substr: "burpsuite", class: ClassBad, name: "burpsuite", conf: 0.95},
	{substr: "hydra", class: ClassBad, name: "hydra", conf: 0.9},

	// Scripted HTTP clients (bad: cannot execute JS challenges).
	{substr: "python-requests", class: ClassBad, name: "python-requests", conf: 0.9},
	{substr: "python-urllib", class: ClassBad, name: "python-urllib", conf: 0.9},
	{substr: "aiohttp", class: ClassBad, name: "aiohttp", conf: 0.85},
	{substr: "httpx", class: ClassBad, name: "httpx", conf: 0.85},
	{substr: "scrapy", class: ClassBad, name: "scrapy", conf: 0.9},
	{substr: "go-http-client", class: ClassBad, name: "go-http-client", conf: 0.9},
	{substr: "okhttp", class: ClassBad, name: "okhttp", conf: 0.85},
	{substr: "java/", class: ClassBad, name: "java-http", conf: 0.8},
	{substr: "apache-httpclient", class: ClassBad, name: "java-httpclient", conf: 0.85},
	{substr: "libwww-perl", class: ClassBad, name: "perl-libwww", conf: 0.9},
	{substr: "curl/", class: ClassBad, name: "curl", conf: 0.9},
	{substr: "wget", class: ClassBad, name: "wget", conf: 0.9},
	{substr: "powershell", class: ClassBad, name: "powershell", conf: 0.8},
	{substr: "axios", class: ClassBad, name: "axios", conf: 0.7},

	// Well-known good crawlers.
	{substr: "googlebot", class: ClassGood, name: "Googlebot", conf: 0.95},
	{substr: "bingbot", class: ClassGood, name: "bingbot", conf: 0.95},
	{substr: "baiduspider", class: ClassGood, name: "Baiduspider", conf: 0.95},
	{substr: "sogou", class: ClassGood, name: "Sogou spider", conf: 0.9},
	{substr: "360spider", class: ClassGood, name: "360Spider", conf: 0.9},
	{substr: "yisouspider", class: ClassGood, name: "YisouSpider", conf: 0.9},
	{substr: "duckduckbot", class: ClassGood, name: "DuckDuckBot", conf: 0.95},
	{substr: "yandexbot", class: ClassGood, name: "YandexBot", conf: 0.95},
	{substr: "applebot", class: ClassGood, name: "Applebot", conf: 0.95},
	{substr: "petalbot", class: ClassGood, name: "PetalBot", conf: 0.9},
	{substr: "bytespider", class: ClassGood, name: "Bytespider", conf: 0.9},
	{substr: "ahrefsbot", class: ClassGood, name: "AhrefsBot", conf: 0.9},
	{substr: "semrushbot", class: ClassGood, name: "SemrushBot", conf: 0.9},
	{substr: "mj12bot", class: ClassGood, name: "MJ12bot", conf: 0.9},
	{substr: "dotbot", class: ClassGood, name: "DotBot", conf: 0.9},
	{substr: "twitterbot", class: ClassGood, name: "Twitterbot", conf: 0.9},
	{substr: "facebookexternalhit", class: ClassGood, name: "Facebook", conf: 0.9},
	{substr: "slackbot", class: ClassGood, name: "Slackbot", conf: 0.9},
	{substr: "telegrambot", class: ClassGood, name: "TelegramBot", conf: 0.9},
	{substr: "linkedinbot", class: ClassGood, name: "LinkedInBot", conf: 0.9},
	{substr: "bot;google", class: ClassGood, name: "Googlebot", conf: 0.9},
	{substr: "adsbot-google", class: ClassGood, name: "AdsBot", conf: 0.9},
	{substr: "feedfetcher", class: ClassGood, name: "FeedFetcher", conf: 0.9},
}

// emptyUAResult is the classification for a missing User-Agent header.
var emptyUAResult = Result{Class: ClassBad, Name: "empty-ua", Confidence: 0.6}

// Match classifies a User-Agent string.
func Match(ua string) Result {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" {
		return emptyUAResult
	}
	for _, r := range uaTable {
		if strings.Contains(ua, r.substr) {
			return Result{Class: r.class, Name: r.name, Confidence: r.conf}
		}
	}
	// Known browser markers push unknown toward benign, but UA spoofing is
	// trivial so confidence stays low.
	if looksLikeBrowser(ua) {
		return Result{Class: ClassUnknown, Name: "browser-like", Confidence: 0.3}
	}
	return Result{Class: ClassUnknown, Name: "unrecognized", Confidence: 0.2}
}

func looksLikeBrowser(ua string) bool {
	for _, m := range []string{"mozilla", "chrome", "safari", "firefox", "edg", "msie", "trident", "opera"} {
		if strings.Contains(ua, m) {
			return true
		}
	}
	return false
}
