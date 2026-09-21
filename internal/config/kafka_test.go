package config

import "testing"

func kafkaShipperCfg(sasl, user, pass string) *Config {
	return &Config{
		ListenHTTP: ":8080",
		LogShipper: &ShipperSettings{
			Type:     "kafka",
			Brokers:  []string{"broker-1.internal:9092"},
			Topic:    "kingmoat-audit",
			SASL:     sasl,
			Username: user,
			Password: pass,
		},
	}
}

// TestValidateKafkaSASLRequiresCredentials: plain / scram-sha256
// authenticate with SASL credentials, so an empty username or password must
// be rejected up front instead of letting the shipper fail its handshake (or
// silently stall) at runtime. "none" / absent need no credentials.
func TestValidateKafkaSASLRequiresCredentials(t *testing.T) {
	if err := kafkaShipperCfg("plain", "", "").Validate(); err == nil {
		t.Fatal("plain without any credentials must be rejected")
	}
	if err := kafkaShipperCfg("plain", "user", "").Validate(); err == nil {
		t.Fatal("plain without password must be rejected")
	}
	if err := kafkaShipperCfg("plain", "", "pass").Validate(); err == nil {
		t.Fatal("plain without username must be rejected")
	}
	if err := kafkaShipperCfg("scram-sha256", "", "pass").Validate(); err == nil {
		t.Fatal("scram-sha256 without username must be rejected")
	}
	if err := kafkaShipperCfg("scram-sha256", "user", "").Validate(); err == nil {
		t.Fatal("scram-sha256 without password must be rejected")
	}
	if err := kafkaShipperCfg("plain", "user", "pass").Validate(); err != nil {
		t.Fatalf("plain with credentials must pass: %v", err)
	}
	if err := kafkaShipperCfg("scram-sha256", "user", "pass").Validate(); err != nil {
		t.Fatalf("scram-sha256 with credentials must pass: %v", err)
	}
	if err := kafkaShipperCfg("none", "", "").Validate(); err != nil {
		t.Fatalf("sasl none needs no credentials: %v", err)
	}
	if err := kafkaShipperCfg("", "", "").Validate(); err != nil {
		t.Fatalf("absent sasl needs no credentials: %v", err)
	}
}
