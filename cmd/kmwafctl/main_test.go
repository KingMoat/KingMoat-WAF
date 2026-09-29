package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsageListsAllCommands(t *testing.T) {
	var buf bytes.Buffer
	usageTo(&buf)
	out := buf.String()
	for _, cmd := range []string{
		"status", "start", "stop", "restart", "config",
		"validate", "hash-password", "reset-password", "upgrade-rollback", "version",
	} {
		if !strings.Contains(out, "kmwafctl "+cmd) {
			t.Fatalf("usage output missing the %q command:\n%s", cmd, out)
		}
	}
	if !strings.Contains(out, "Usage: kmwafctl <command> [flags]") {
		t.Fatalf("usage output missing the usage line:\n%s", out)
	}
	if strings.Contains(out, "kingmoat-cli") {
		t.Fatalf("usage output still references kingmoat-cli:\n%s", out)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var buf bytes.Buffer
	usageTo(&buf)
	if code := run([]string{"nope"}); code != 2 {
		t.Fatalf("run(unknown) = %d, want 2", code)
	}
	if code := run(nil); code != 2 {
		t.Fatalf("run(nil) = %d, want 2", code)
	}
}

func TestRunHelpExitZero(t *testing.T) {
	var buf bytes.Buffer
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan int, 1)
	go func() { done <- run([]string{"--help"}) }()
	code := <-done
	os.Stdout = oldStdout
	_ = w.Close()
	_, _ = buf.ReadFrom(r)
	if code != 0 {
		t.Fatalf("run(--help) = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "kmwafctl reset-password") {
		t.Fatalf("--help output incomplete:\n%s", buf.String())
	}
}

func TestRunVersionOutput(t *testing.T) {
	var buf bytes.Buffer
	if code := cmdVersion(nil, &buf); code != 0 {
		t.Fatalf("cmdVersion exit = %d, want 0", code)
	}
	if got := strings.TrimSpace(buf.String()); !strings.HasPrefix(got, "kmwafctl ") {
		t.Fatalf("version output = %q, want the kmwafctl prefix", got)
	}
	if strings.Contains(buf.String(), "kingmoat-cli") {
		t.Fatalf("version output = %q, still references kingmoat-cli", buf.String())
	}
}

func TestDeriveDataDir(t *testing.T) {
	oldRecords, oldCandidates := installRecordPaths, dataDirCandidates
	t.Cleanup(func() { installRecordPaths, dataDirCandidates = oldRecords, oldCandidates })

	dir := t.TempDir()
	record := filepath.Join(dir, "kingmoatwaf-install.conf")
	if err := os.WriteFile(record, []byte("INSTALL_DIR=\"/opt/kingmoatwaf\"\nDATA_DIR=\"/data/from-record\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installRecordPaths = []string{record}
	dataDirCandidates = nil
	if got := deriveDataDir(); got != "/data/from-record" {
		t.Fatalf("deriveDataDir = %q, want the record value", got)
	}

	if err := os.WriteFile(record, []byte("INSTALL_DIR=\"/opt/kingmoatwaf\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	detected := t.TempDir()
	dataDirCandidates = []string{detected}
	if got := deriveDataDir(); got != detected {
		t.Fatalf("deriveDataDir = %q, want the detected dir %q", got, detected)
	}

	dataDirCandidates = nil
	if got := deriveDataDir(); got != newLayoutDataDir {
		t.Fatalf("deriveDataDir = %q, want the new-layout default", got)
	}
}

func TestUpgradeRollbackDerivesServerBinaryName(t *testing.T) {
	if serverBinaryName != "kingmoatwaf" {
		t.Fatalf("serverBinaryName = %q, want kingmoatwaf", serverBinaryName)
	}
	if unitName != "kingmoatwaf.service" {
		t.Fatalf("unitName = %q, want kingmoatwaf.service", unitName)
	}
}

func TestServiceCommandNamesInDispatch(t *testing.T) {
	restoreSeams(t)
	systemdHost = func() bool { return true }
	var code int
	msg := captureStderr(t, func() { code = runServiceCommand("bogus", nil) })
	if code != 2 {
		t.Fatalf("runServiceCommand(bogus) = %d, want 2", code)
	}
	if msg != "" {
		t.Fatalf("unexpected stderr for a dispatched-but-unknown command: %q", msg)
	}
}
