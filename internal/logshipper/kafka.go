package logshipper

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// kafkaTarget wraps a kafka.Writer: one JSON message per audit event, keyed
// by trace_id when present so retries and partitioning keep event ordering
// per request.
type kafkaTarget struct {
	writer *kafka.Writer
}

// newKafkaTarget builds the writer from the shipper settings. TLS and SASL
// (plain / scram-sha256) are optional; the transport mirrors the in-product
// decision for upstream TLS: certificates are not verified by default so
// self-signed internal brokers work zero-config.
func newKafkaTarget(cfg config.ShipperSettings) (*kafkaTarget, error) {
	brokers := make([]string, 0, len(cfg.Brokers))
	for _, b := range cfg.Brokers {
		if t := strings.TrimSpace(b); t != "" {
			brokers = append(brokers, t)
		}
	}
	if len(brokers) == 0 {
		return nil, fmt.Errorf("logshipper: kafka brokers is required")
	}
	topic := strings.TrimSpace(cfg.Topic)
	if topic == "" {
		return nil, fmt.Errorf("logshipper: kafka topic is required")
	}
	tr := &kafka.Transport{DialTimeout: 5 * time.Second}
	if cfg.UseTLS {
		// tls_skip_verify absent keeps the legacy zero-config behavior for
		// internal self-signed brokers (certificates not verified); an
		// explicit false turns broker-certificate verification on.
		skip := true
		if cfg.TLSSkipVerify != nil {
			skip = *cfg.TLSSkipVerify
		}
		tr.TLS = &tls.Config{InsecureSkipVerify: skip}
	}
	mech, err := kafkaSASLMechanism(cfg)
	if err != nil {
		return nil, err
	}
	tr.SASL = mech
	w := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireOne,
		BatchSize:    256,
		BatchTimeout: 50 * time.Millisecond,
		WriteTimeout: 30 * time.Second,
		Transport:    tr,
	}
	return &kafkaTarget{writer: w}, nil
}

func kafkaSASLMechanism(cfg config.ShipperSettings) (sasl.Mechanism, error) {
	switch cfg.SASL {
	case "", "none":
		return nil, nil
	case "plain":
		return plain.Mechanism{Username: cfg.Username, Password: cfg.Password}, nil
	case "scram-sha256":
		return scram.Mechanism(scram.SHA256, cfg.Username, cfg.Password)
	default:
		return nil, fmt.Errorf("logshipper: kafka sasl %q not supported", cfg.SASL)
	}
}

// pushBatch ships one batch of audit events as JSON messages. A transport
// error is returned to the push layer (warn + drop counting semantics, same
// as the s3 sink).
func (t *kafkaTarget) pushBatch(batch []logstore.Event) error {
	msgs := make([]kafka.Message, 0, len(batch))
	for i := range batch {
		b, err := json.Marshal(batch[i])
		if err != nil {
			continue
		}
		m := kafka.Message{Value: b}
		if batch[i].TraceID != "" {
			m.Key = []byte(batch[i].TraceID)
		}
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return t.writer.WriteMessages(ctx, msgs...)
}

func (t *kafkaTarget) close() error { return t.writer.Close() }
