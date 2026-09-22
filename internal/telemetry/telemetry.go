// Package telemetry — 安装统计与升级检查客户端（KingMoat WAF 社区版）
//
// 策略（2026-09-21 拍板）：
//
//   - 默认关闭：仅在配置 telemetry.enabled=true 时启动（缺省零请求）
//   - 首次启用后触发上报；连续 3 次无法到达端点则写持久化停止标记并退出，
//     后续启动不再尝试（设置开关 关→开 可清除标记重新尝试）
//   - 隐私：字段白名单（随机 uid / 版本 / OS / 架构 / CPU 核数 / 安装方式），
//     不采集主机名、用户名、MAC、内网 IP、文件路径与业务数据；
//     DO_NOT_TRACK 环境变量命中时零请求零落盘
//
// 上报在独立 goroutine 中运行，不阻塞启动，失败静默。
package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Config 客户端配置
type Config struct {
	// Endpoint 遥测服务地址（必填）
	Endpoint string

	// Version 当前软件版本（必填）
	Version string

	// AppName 应用名，用于持久化目录 ~/.config/<AppName>/
	AppName string

	// Product 产品标识，多产品共用一个上报后端时用于区分统计归属。
	Product string

	// InstallMethod 安装方式：docker / binary / package / source
	InstallMethod string

	// Extra 产品自定义补充字段（服务端强校验，最多 8 个键）
	Extra map[string]string

	// IDFile 覆盖 uid 持久化路径（建议指向数据目录，升级不丢 uid）
	IDFile string

	// Disable 用户主动关闭遥测（opt-out 信标）
	Disable bool

	// HTTPTimeout 单次上报超时（默认 5 秒）
	HTTPTimeout time.Duration

	// InitialDelay 启动后延迟多久做首次上报（默认 3 秒）
	InitialDelay time.Duration
}

// Response 服务端返回
type Response struct {
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	UpdateURL       string `json:"update_url"`
	ReportIntervalH int    `json:"report_interval_hours"`
	ServerTime      int64  `json:"server_time"`
	InstallToken    string `json:"install_token"`
	Registered      bool   `json:"registered"`
	Product         string `json:"product"`
	Error           string `json:"error"`
}

// Telemetry 遥测客户端实例（并发安全）
type Telemetry struct {
	cfg       Config
	uid       string
	token     string
	disabled  bool
	failCount int // 连续失败次数（达到 failStopAfter 停报）
	mu        sync.Mutex
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	lastResp  *Response
}

// failStopAfter 连续失败多少次后永久停止（persisted via "stopped" flag）。
var failStopAfter = 3

// probeBackoffs 失败重试退避序列（测试可注入更短值）。
var probeBackoffs = []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second}

// LastResponse 返回最近一次成功上报的服务端响应（拷贝）；未成功过返回 nil。
func (t *Telemetry) LastResponse() *Response {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastResp == nil {
		return nil
	}
	cp := *t.lastResp
	return &cp
}

func (t *Telemetry) isDisabled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.disabled
}

// envOptOut 读取行业标准隐私开关 DO_NOT_TRACK。
func envOptOut() bool {
	v := strings.TrimSpace(os.Getenv("DO_NOT_TRACK"))
	return v != "" && v != "0" && !strings.EqualFold(v, "false")
}

var (
	reProduct  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	reExtraKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,31}$`)
	reExtraVal = regexp.MustCompile(`^[A-Za-z0-9 ._:/@=+,-]{0,63}$`)
)

const (
	maxExtraKeys = 8
	maxExtraVal  = 64
	maxExtraKey  = 32
	maxOSVer     = 64
)

var reservedExtraKeys = map[string]bool{
	"uid": true, "version": true, "opt_out": true, "product": true,
	"os": true, "arch": true, "os_version": true, "go_version": true,
	"cpu_count": true, "install_method": true, "ip": true, "token": true,
	"country": true, "extra": true,
}

// New 创建遥测客户端（不发送任何请求）。
// DO_NOT_TRACK 命中时不落盘任何本地状态（既不上报也不生成可关联的 ID）。
func New(cfg Config) *Telemetry {
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	if cfg.InitialDelay <= 0 {
		cfg.InitialDelay = 3 * time.Second
	}
	if cfg.Product != "" && !reProduct.MatchString(cfg.Product) {
		cfg.Product = ""
	}
	t := &Telemetry{cfg: cfg}
	if envOptOut() {
		return t
	}
	t.uid = t.loadOrCreateID()
	t.token = t.loadToken()
	t.disabled = t.readFlag("disabled")
	return t
}

// Start 启动遥测（异步）。以下情况为 no-op：未启用端点、DO_NOT_TRACK、
// 用户已 opt-out、存在 3 次不可达的持久化停止标记。
func (t *Telemetry) Start() {
	if t.cfg.Endpoint == "" || t.uid == "" {
		return
	}
	if envOptOut() {
		return
	}
	if t.cfg.Disable {
		if !t.isDisabled() {
			t.report(true)
			t.writeFlag("disabled")
			t.mu.Lock()
			t.disabled = true
			t.mu.Unlock()
		}
		return
	}
	if t.isDisabled() {
		return
	}
	if t.readFlag("stopped") {
		return // 连续 3 次不可达已永久停止；开关 关→开 可清除标记重试
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		select {
		case <-time.After(t.cfg.InitialDelay):
		case <-ctx.Done():
			return
		}
		attempt := 0
		for {
			intervalH, ok := t.report(false)
			if ok {
				t.mu.Lock()
				t.failCount = 0
				t.mu.Unlock()
				if intervalH <= 0 {
					intervalH = 24
				}
				attempt = 0
				select {
				case <-time.After(time.Duration(intervalH) * time.Hour):
				case <-ctx.Done():
					return
				}
				continue
			}
			// 失败：连续计数达到上限则持久化停止
			t.mu.Lock()
			attempt++
			t.failCount = attempt
			t.mu.Unlock()
			if attempt >= failStopAfter {
				t.writeFlag("stopped")
				t.mu.Lock()
				t.disabled = true
				t.mu.Unlock()
				return // 连续 3 次不可达：静默永久停止（开关 关→开 可重试）
			}
			backoff := probeBackoffs[attempt-1]
			if attempt-1 >= len(probeBackoffs) {
				backoff = probeBackoffs[len(probeBackoffs)-1]
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop 停止遥测（阻塞至上报 goroutine 退出）。
func (t *Telemetry) Stop() {
	if t.cancel != nil {
		t.cancel()
	}
	t.wg.Wait()
}

// Disable 运行时关闭遥测（opt-out 信标 + 本地标记）。
func (t *Telemetry) Disable() {
	t.mu.Lock()
	if t.disabled {
		t.mu.Unlock()
		return
	}
	t.disabled = true
	cancel := t.cancel
	t.mu.Unlock()

	t.report(true)
	t.writeFlag("disabled")
	if cancel != nil {
		cancel()
	}
}

// ResetStopFlag 清除「3 次不可达」持久化停止标记并重置失败计数，
// 供设置开关 关→开 时给用户一个重新尝试的入口。
func (t *Telemetry) ResetStopFlag() {
	t.mu.Lock()
	t.failCount = 0
	t.disabled = false
	t.mu.Unlock()
	if t.uid != "" {
		_ = os.Remove(t.filePath("stopped"))
	}
}

// payload 上报体
type payload struct {
	UID           string            `json:"uid"`
	Version       string            `json:"version"`
	Product       string            `json:"product,omitempty"`
	OS            string            `json:"os,omitempty"`
	Arch          string            `json:"arch,omitempty"`
	OSVersion     string            `json:"os_version,omitempty"`
	GoVersion     string            `json:"go_version,omitempty"`
	CPUCount      int               `json:"cpu_count,omitempty"`
	InstallMethod string            `json:"install_method,omitempty"`
	Extra         map[string]string `json:"extra,omitempty"`
	OptOut        bool              `json:"opt_out,omitempty"`
}

// report 执行一次上报；成功返回服务端建议间隔（小时）与 true，失败返回 false。
func (t *Telemetry) report(optOut bool) (int, bool) {
	if t.cfg.Endpoint == "" || t.uid == "" {
		return 0, false
	}
	p := payload{
		UID:           t.uid,
		Version:       clip(t.cfg.Version, 32),
		Product:       t.cfg.Product,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		OSVersion:     collectOSVersion(),
		GoVersion:     clip(runtime.Version(), 16),
		CPUCount:      runtime.NumCPU(),
		InstallMethod: clip(t.cfg.InstallMethod, 32),
		Extra:         sanitizeExtra(t.cfg.Extra),
		OptOut:        optOut,
	}
	body, err := json.Marshal(p)
	if err != nil {
		return 0, false
	}
	req, err := http.NewRequest(http.MethodPost, t.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, false
	}
	req.Header.Set("Content-Type", "application/json")
	t.mu.Lock()
	tok := t.token
	t.mu.Unlock()
	if tok != "" {
		req.Header.Set("X-Telemetry-Token", tok)
	}

	client := &http.Client{Timeout: t.cfg.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false // 静默失败
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		t.mu.Lock()
		t.token = ""
		t.mu.Unlock()
		_ = os.Remove(t.filePath("token"))
		return 0, false
	case http.StatusTooManyRequests:
		return 0, false
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false
	}

	var r Response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, false
	}

	if r.InstallToken != "" {
		t.mu.Lock()
		t.token = r.InstallToken
		t.mu.Unlock()
		t.saveToken(r.InstallToken)
	}
	if !optOut {
		t.mu.Lock()
		t.lastResp = &r
		t.mu.Unlock()
	}
	return r.ReportIntervalH, true
}

var osVersionOnce sync.Once
var osVersionCached string

// collectOSVersion 尽力获取系统发行版名称（Linux 读 /etc/os-release；
// 其他平台留空——宁可不采集，也不调用外部命令）。
func collectOSVersion() string {
	osVersionOnce.Do(func() {
		if runtime.GOOS != "linux" {
			return
		}
		b, err := os.ReadFile("/etc/os-release")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "PRETTY_NAME=") {
				continue
			}
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			v = strings.Trim(v, `"`)
			osVersionCached = clip(strings.TrimSpace(v), maxOSVer)
			return
		}
	})
	return osVersionCached
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func sanitizeExtra(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if len(out) >= maxExtraKeys {
			break
		}
		if reservedExtraKeys[strings.ToLower(k)] {
			continue
		}
		if len(k) > maxExtraKey || !reExtraKey.MatchString(k) {
			continue
		}
		v = clip(v, maxExtraVal)
		if v != "" && !reExtraVal.MatchString(v) {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (t *Telemetry) configDir() string {
	if t.cfg.IDFile != "" {
		return filepath.Dir(t.cfg.IDFile)
	}
	app := t.cfg.AppName
	if app == "" {
		app = "telemetry"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".config", app)
}

// stateSuffix：token / disabled / stopped 标记按产品隔离（服务端 token 绑定
// 在 (uid, product) 上）。
func (t *Telemetry) stateSuffix() string {
	if t.cfg.Product == "" {
		return ""
	}
	return "." + t.cfg.Product
}

func (t *Telemetry) filePath(name string) string {
	return filepath.Join(t.configDir(), name+t.stateSuffix())
}

func (t *Telemetry) loadOrCreateID() string {
	path := t.cfg.IDFile
	if path == "" {
		path = filepath.Join(t.configDir(), "telemetry_id")
	}
	if data, err := os.ReadFile(path); err == nil {
		if id := string(bytes.TrimSpace(data)); len(id) >= 8 && len(id) <= 64 {
			return id
		}
	}
	id := generateUUIDv4()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte(id), 0o600)
	return id
}

func (t *Telemetry) loadToken() string {
	if data, err := os.ReadFile(t.filePath("token")); err == nil {
		return string(bytes.TrimSpace(data))
	}
	return ""
}

func (t *Telemetry) saveToken(tok string) {
	_ = os.MkdirAll(t.configDir(), 0o755)
	_ = os.WriteFile(t.filePath("token"), []byte(tok), 0o600)
}

func (t *Telemetry) readFlag(name string) bool {
	_, err := os.Stat(t.filePath(name))
	return err == nil
}

func (t *Telemetry) writeFlag(name string) {
	_ = os.MkdirAll(t.configDir(), 0o755)
	_ = os.WriteFile(t.filePath(name), []byte("1"), 0o600)
}

func generateUUIDv4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
