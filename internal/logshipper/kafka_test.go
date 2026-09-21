package logshipper

import (
	"testing"

	"github.com/segmentio/kafka-go"

	"github.com/kingmoat/kingmoat/internal/config"
)

func boolPtr(b bool) *bool { return &b }

// TestKafkaTLSSkipVerifyKnob pins the broker-certificate verification knob:
// absent tls_skip_verify keeps the legacy zero-config behavior (internal
// self-signed brokers, certificates NOT verified); an explicit false turns
// chain verification on.
func TestKafkaTLSSkipVerifyKnob(t *testing.T) {
	base := config.ShipperSettings{
		Type:    "kafka",
		Brokers: []string{"broker-1.internal:9092"},
		Topic:   "kingmoat-audit",
		UseTLS:  true,
	}
	cases := []struct {
		name string
		skip *bool
		want bool
	}{
		{"absent keeps legacy skip-verify", nil, true},
		{"explicit true skips verification", boolPtr(true), true},
		{"explicit false verifies broker chain", boolPtr(false), false},
	}
	for _, tc := range cases {
		cfg := base
		cfg.TLSSkipVerify = tc.skip
		tgt, err := newKafkaTarget(cfg)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		tr, ok := tgt.writer.Transport.(*kafka.Transport)
		if !ok || tr.TLS == nil {
			t.Fatalf("%s: kafka transport/TLS config missing", tc.name)
		}
		if tr.TLS.InsecureSkipVerify != tc.want {
			t.Fatalf("%s: InsecureSkipVerify = %v, want %v", tc.name, tr.TLS.InsecureSkipVerify, tc.want)
		}
	}
}

// TestKafkaPlaintextIgnoresVerifyKnob: without use_tls no TLS config is
// built at all, regardless of the knob.
func TestKafkaPlaintextIgnoresVerifyKnob(t *testing.T) {
	cfg := config.ShipperSettings{
		Type:          "kafka",
		Brokers:       []string{"broker-1.internal:9092"},
		Topic:         "kingmoat-audit",
		TLSSkipVerify: boolPtr(false),
	}
	tgt, err := newKafkaTarget(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := tgt.writer.Transport.(*kafka.Transport); ok && tr.TLS != nil {
		t.Fatal("plaintext kafka transport must not carry a TLS config")
	}
}
