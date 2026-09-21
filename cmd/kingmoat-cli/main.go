// Command kingmoat-cli provides offline tooling for KingMoat: config
// validation with dry-run WAF compilation (catches SecLang syntax errors
// before they reach the data plane).
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/coraza"
	"github.com/kingmoat/kingmoat/internal/passhash"
	"github.com/kingmoat/kingmoat/internal/store"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "validate":
		runValidate(os.Args[2:])
	case "hash-password":
		runHashPassword(os.Args[2:])
	case "reset-password":
		runResetPassword(os.Args[2:])
	case "version":
		fmt.Println("kingmoat-cli", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `kingmoat-cli (%s)

Usage:
  kingmoat-cli validate -config <path>   Validate config and dry-run build every WAF instance
  kingmoat-cli hash-password -password <pw>   Generate an argon2id hash (avoids shell history with -stdin)
  kingmoat-cli reset-password -db <path> -username <user> [-password <pw> | -generate] [-clear-mfa]
                                         Console password reset (offline rescue): the account is
                                         forced to change the password at its next login.
  kingmoat-cli version                   Print version
`, version)
}

// runResetPassword is the offline console-password rescue: it updates the
// users table directly (no running console required), forces a password
// change at next login and records an audit entry.
func runResetPassword(args []string) {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	dbPath := fs.String("db", "", "path to the console SQLite store (kingmoat.db)")
	username := fs.String("username", "", "account whose password is reset")
	password := fs.String("password", "", "new password (omit together with -generate to auto-generate)")
	generate := fs.Bool("generate", false, "generate a random temporary password and print it")
	clearMFA := fs.Bool("clear-mfa", false, "also clear the account's TOTP enrolment (MFA device lost)")
	_ = fs.Parse(args)
	if strings.TrimSpace(*dbPath) == "" || strings.TrimSpace(*username) == "" {
		fmt.Fprintln(os.Stderr, "reset-password: -db and -username are required")
		os.Exit(2)
	}
	user := strings.TrimSpace(*username)
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset-password: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.GetUser(user); err != nil {
		fmt.Fprintf(os.Stderr, "reset-password: account %q not found (%v)\n", user, err)
		os.Exit(1)
	}
	pw := *password
	generated := false
	if pw == "" || *generate {
		pw, err = randomPassword()
		if err != nil {
			fmt.Fprintf(os.Stderr, "reset-password: generate password: %v\n", err)
			os.Exit(1)
		}
		generated = true
	}
	if len(pw) < 8 {
		fmt.Fprintln(os.Stderr, "reset-password: password must be at least 8 characters")
		os.Exit(2)
	}
	hash, err := passhash.HashPassword(pw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset-password: hash: %v\n", err)
		os.Exit(1)
	}
	if err := st.ResetUserPassword(user, hash); err != nil {
		fmt.Fprintf(os.Stderr, "reset-password: %v\n", err)
		os.Exit(1)
	}
	if *clearMFA {
		if err := st.DisableUserTOTP(user); err != nil {
			fmt.Fprintf(os.Stderr, "reset-password: clear MFA: %v\n", err)
			os.Exit(1)
		}
	}
	_ = st.RecordChange("cli-rescue", "admin", "user.reset_password", user,
		"offline CLI reset (password change forced at next login)")
	fmt.Printf("password reset for %q (must change at next login)\n", user)
	if generated {
		fmt.Printf("temporary password: %s\n", pw)
	}
	if *clearMFA {
		fmt.Println("MFA enrolment cleared")
	}
}

// randomPassword returns a 20-char alphanumeric one-time password.
func randomPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, 20)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[n.Int64()]
	}
	return string(buf), nil
}

// runHashPassword emits an argon2id encoded hash suitable for the
// KINGMOAT_ADMIN_HASH environment variable (verified by the console auth).
func runHashPassword(args []string) {
	fs := flag.NewFlagSet("hash-password", flag.ExitOnError)
	pw := fs.String("password", "", "password to hash")
	stdin := fs.Bool("stdin", false, "read the password from stdin instead of -password (recommended: avoids shell history and process list exposure)")
	_ = fs.Parse(args)
	password := strings.TrimSpace(*pw)
	if password == "" && *stdin {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil || len(b) == 0 {
			fmt.Fprintln(os.Stderr, "hash-password: failed to read password from stdin")
			os.Exit(2)
		}
		password = strings.TrimRight(string(b), "\r\n")
	}
	if password == "" {
		fmt.Fprintln(os.Stderr, "hash-password: provide -password or -stdin (recommended; -password is visible in shell history and the process list)")
		os.Exit(2)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		fmt.Fprintln(os.Stderr, "hash-password: salt generation failed")
		os.Exit(1)
	}
	const (
		timeCost = 3
		memory   = 64 * 1024
		threads  = 4
		keyLen   = 32
	)
	key := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, keyLen)
	fmt.Printf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s\n",
		argon2.Version, memory, timeCost, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := fs.String("config", "config.json", "path to the JSON config file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("config OK: %s (%d sites)\n", *path, len(cfg.Sites))

	// Dry-run: compile every enabled site's WAF (embedded CRS + custom rules).
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stage, err := coraza.New(cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: WAF build: %v\n", err)
		os.Exit(1)
	}
	built := 0
	for i := range cfg.Sites {
		if cfg.Sites[i].WAF.IsEnabled() {
			built++
		}
	}
	fmt.Printf("WAF OK: %d/%d sites with detection enabled (CRS 4.x compiled)\n", built, len(cfg.Sites))
	fmt.Println("validate: PASS")
	_ = stage
}
