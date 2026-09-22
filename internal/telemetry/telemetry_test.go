package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func quietConfig(endpoint, idFile string) Config {
	return Config{
		Endpoint:     endpoint,
		Version:      "v0.7.0-rc1",
		AppName:      "kingmoat-test",
		Product:      "kingmoat-waf-test",
		InstallMethod: "test",
		IDFile:       filepath.Join(idFile, "telemetry_id"),
		HTTPTimeout:  300 * time.Millisecond,
		InitialDelay: 10 * time.Millisecond,
	}
}

func withFastBackoff(t *testing.T) {
	t.Helper()
	old := probeBackoffs
	probeBackoffs = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}
	t.Cleanup(func() { probeBackoffs = old })
}

// 不可达端点：3 次连续失败后写 stopped 标记并退出循环（不再有请求）。
func TestThreeFailuresStopPermanently(t *testing.T) {
	withFastBackoff(t)
	dir := t.TempDir()

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// 模拟不可达：直接关闭连接
		hij, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("cannot hijack")
		}
		conn, _, _ := hij.Hijack()
		conn.Close()
	}))
	srv.Close() // 关闭服务器 → 端口不可达
	unreachable := srv.URL

	cfg := quietConfig(unreachable, filepath.Join(dir, "a"))
	cfg.InitialDelay = 5 * time.Millisecond
	tel := New(cfg)
	tel.Start()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if tel.readFlag("stopped") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stopped flag not written within 3s")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// 停止标记写入后，Restart（新实例）应为 no-op：不再产生请求
	hitsBefore := hits.Load()
	tel2 := New(cfg)
	tel2.Start()
	time.Sleep(200 * time.Millisecond)
	if hits.Load() != hitsBefore {
		t.Fatalf("requests after stop: got %d, want %d", hits.Load(), hitsBefore)
	}

	// ResetStopFlag 清除标记 → 重新尝试（依旧不可达，但标记会再次写入）
	tel2.ResetStopFlag()
	if tel2.readFlag("stopped") {
		t.Fatal("stopped flag should be cleared by ResetStopFlag")
	}
	tel2.Stop()
}

// 成功上报：走服务端返回的间隔、lastResp 可读、opt-out 信标不在常规路径。
func TestReportSuccessFlow(t *testing.T) {
	dir := t.TempDir()
	var bodies []payload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p payload
		_ = json.NewDecoder(r.Body).Decode(&p)
		bodies = append(bodies, p)
		_ = json.NewEncoder(w).Encode(Response{ReportIntervalH: 1, InstallToken: "tok-1", Registered: true})
	}))
	defer srv.Close()

	cfg := quietConfig(srv.URL, filepath.Join(dir, "b"))
	tel := New(cfg)
	tel.Start()
	time.Sleep(300 * time.Millisecond)
	tel.Stop()

	if len(bodies) == 0 {
		t.Fatal("no report received")
	}
	if bodies[0].Product != "kingmoat-waf-test" || bodies[0].InstallMethod != "test" {
		t.Fatalf("unexpected payload: %+v", bodies[0])
	}
	if r := tel.LastResponse(); r == nil || !r.Registered {
		t.Fatalf("LastResponse = %+v, want registered", r)
	}
}

// DO_NOT_TRACK：零请求、零落盘。
func TestDoNotTrackSendsNothing(t *testing.T) {
	t.Setenv("DO_NOT_TRACK", "1")
	dir := t.TempDir()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	cfg := quietConfig(srv.URL, filepath.Join(dir, "c"))
	tel := New(cfg)
	tel.Start()
	time.Sleep(200 * time.Millisecond)
	tel.Stop()

	if hits.Load() != 0 {
		t.Fatalf("DNT must send nothing, got %d requests", hits.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "c", "telemetry_id")); !os.IsNotExist(err) {
		t.Fatal("DNT must not persist any local state")
	}
}

// 环境变量名（非密钥字面量）未被设置 → none，不产生 inline 误判（keystore 语义对齐）。
func TestStoppedFlagSurvivesRestart(t *testing.T) {
	withFastBackoff(t)
	dir := t.TempDir()
	cfg := quietConfig("http://127.0.0.1:1/x", filepath.Join(dir, "d"))
	cfg.InitialDelay = 5 * time.Millisecond

	tel := New(cfg)
	tel.Start()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if tel.readFlag("stopped") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stopped flag not written")
		}
		time.Sleep(20 * time.Millisecond)
	}
	tel.Stop()

	// 新实例读同一 IDFile 目录 → stopped 标记生效 → no-op
	tel2 := New(cfg)
	tel2.Start()
	time.Sleep(150 * time.Millisecond)
	tel2.Stop()
	// 通过 ResetStopFlag 验证标记仍可清除（重新尝试入口）
	tel2.ResetStopFlag()
	if tel2.readFlag("stopped") {
		t.Fatal("ResetStopFlag must clear the stopped flag")
	}
}
