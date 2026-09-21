// SMTP email notifier: supports implicit TLS (465) and STARTTLS (25/587).
// Used by the WAF alert engine to deliver alert messages.
package alerting

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// EmailNotifier sends alert emails through SMTP.
type EmailNotifier struct {
	cfg config.EmailSettings
}

// NewEmailNotifier builds the notifier.
func NewEmailNotifier(cfg config.EmailSettings) *EmailNotifier { return &EmailNotifier{cfg: cfg} }

// Send delivers one alert email to all recipients.
func (n *EmailNotifier) Send(subject, body string) error {
	if !n.cfg.Enabled {
		return nil
	}
	addr := net.JoinHostPort(n.cfg.Host, fmt.Sprintf("%d", n.cfg.Port))
	from := n.cfg.From
	msg := buildMessage(from, n.cfg.To, subject, body)

	var client *smtp.Client
	var err error
	// smtp.Client has no internal timeouts: every operation below would hang
	// forever on a stalled server, blocking the alert engine loop. Bound the
	// whole session (dial + greeting + auth + data + quit) with one deadline.
	const emailDeadline = 30 * time.Second
	if n.cfg.SSL {
		conn, derr := tls.Dial("tcp", addr, &tls.Config{ServerName: n.cfg.Host})
		if derr != nil {
			return fmt.Errorf("email: dial ssl: %w", derr)
		}
		_ = conn.SetDeadline(time.Now().Add(emailDeadline))
		client, err = smtp.NewClient(conn, n.cfg.Host)
	} else {
		conn, derr := net.DialTimeout("tcp", addr, 15*time.Second)
		if derr != nil {
			return fmt.Errorf("email: dial: %w", derr)
		}
		_ = conn.SetDeadline(time.Now().Add(emailDeadline))
		client, err = smtp.NewClient(conn, n.cfg.Host)
		if err == nil {
			if ok, _ := client.Extension("STARTTLS"); ok {
				if err = client.StartTLS(&tls.Config{ServerName: n.cfg.Host}); err != nil {
					client.Close()
					return fmt.Errorf("email: starttls: %w", err)
				}
			}
		}
	}
	if err != nil {
		return fmt.Errorf("email: handshake: %w", err)
	}
	defer client.Close()

	if n.cfg.Username != "" {
		auth := smtp.PlainAuth("", n.cfg.Username, n.cfg.Password, n.cfg.Host)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("email: auth: %w", err)
		}
	}
	if err = client.Mail(from); err != nil {
		return fmt.Errorf("email: mail from: %w", err)
	}
	for _, to := range n.cfg.To {
		if err = client.Rcpt(strings.TrimSpace(to)); err != nil {
			return fmt.Errorf("email: rcpt %s: %w", to, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email: data: %w", err)
	}
	if _, err = w.Write(msg); err != nil {
		w.Close()
		return fmt.Errorf("email: write: %w", err)
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("email: close data: %w", err)
	}
	return client.Quit()
}

func buildMessage(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// Notify implements the alerts.Notifier contract: delivers the alert email.
func (n *EmailNotifier) Notify(subject, body string) error {
	return n.Send(subject, body)
}
