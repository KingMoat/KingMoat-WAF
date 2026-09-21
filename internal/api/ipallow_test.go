package api

import "testing"

func TestIPAllowed(t *testing.T) {
	allowed := []string{"10.0.0.0/8", "192.168.1.100"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"10.0.0.1", true},
		{"192.168.1.100", true},
		{"192.168.1.101", false},
		{"11.0.0.1", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := ipAllowed(c.ip, allowed); got != c.want {
			t.Errorf("ipAllowed(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
	// empty list = allow all
	if !ipAllowed("1.2.3.4", nil) {
		t.Fatal("empty list must allow")
	}
}
