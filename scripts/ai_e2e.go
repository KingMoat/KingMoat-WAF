//go:build ignore

// AI chain e2e: publish ai config via API, verify the assistant hot-rebuilds
// and /api/ai/config reports enabled + api_key_set.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
)

func main() {
	base := "http://127.0.0.1:18899"
	client := &http.Client{}

	// login
	lr, err := client.Post(base+"/api/login", "application/json",
		bytes.NewReader([]byte(`{"password":"`+os.Getenv("KM_PW")+`"}`)))
	if err != nil {
		fmt.Println("login err:", err)
		return
	}
	var cookie string
	for _, c := range lr.Cookies() {
		if c.Name == "km_session" {
			cookie = c.Name + "=" + c.Value
		}
	}
	lr.Body.Close()

	do := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, base+path, bytes.NewReader([]byte(body)))
		req.Header.Set("Cookie", cookie)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b := make([]byte, 800)
		n, _ := resp.Body.Read(b)
		return resp.StatusCode, string(b[:n])
	}

	// 1. enable ai in config (publish)
	st, sb := do("GET", "/api/config", "")
	fmt.Println("get config:", st)
	_ = sb
	aiCfg := `{"note":"ai-toggle","config":{"listen_http":":18080","sites":[{"domains":["a.local"],"upstream":{"nodes":[{"address":"127.0.0.1:19099"}]}}],"ai":{"enabled":true,"provider":{"template":"openai","base_url":"https://api.openai.com/v1","model":"gpt-4o-mini","api_key_env":"KINGMOAT_AI_API_KEY"}}}}`
	st, sb = do("POST", "/api/config/publish", aiCfg)
	fmt.Println("publish ai:", st, sb)

	// 2. ai config
	st, sb = do("GET", "/api/ai/config", "")
	fmt.Println("ai/config:", st, sb)

	// 3. chat (no key set → provider error at request time, but endpoint alive)
	st, sb = do("POST", "/api/ai/chat", `{"message":"hi"}`)
	fmt.Println("ai/chat:", st, sb[:min(200, len(sb))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
