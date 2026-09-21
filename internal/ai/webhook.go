package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// postWebhook delivers a generic JSON payload (best-effort, 5s timeout).
func postWebhook(url string, payload any) error {
	if url == "" {
		return nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
