// Command gen-licenses produces THIRD-PARTY-LICENSES from the Go module
// cache: every non-stdlib module compiled into ./... is listed with its
// version, its license files and their full texts.
//
// With -check it instead verifies that every detected license is on the
// permissive allowlist required by docs/ARCHITECTURE.md §12.1 (Apache-2.0,
// MIT, BSD-2-Clause, BSD-3-Clause, ISC; public-domain notices and pure
// attribution files are also accepted) and exits non-zero on violations.
// That check is the license-scan gate of the CI pipeline.
//
// Usage:
//
//	go run ./scripts/gen-licenses [-out THIRD-PARTY-LICENSES] [-check]
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	copyleftRe  = regexp.MustCompile(`(?i)(GNU (General|Lesser|Affero) Public License|\bGPLv?[23]\b|Mozilla Public License|\bAGPL\b|\bLGPL\b)`)
	apacheRe    = regexp.MustCompile(`(?i)Apache License.*Version 2\.0|www\.apache\.org/licenses`)
	bsd2Re      = regexp.MustCompile(`(?i)BSD[- ]2[- ]Clause`)
	bsd3Re      = regexp.MustCompile(`(?i)BSD[- ]3[- ]Clause`)
	iscRe       = regexp.MustCompile(`(?i)ISC License|Permission to use, copy, modify, and/or distribute`)
	mitRe       = regexp.MustCompile(`(?i)MIT (License|LICENSE)|Permission is hereby granted, free of charge`)
	pdomainRe   = regexp.MustCompile(`(?i)public domain`)
	redistribRe = regexp.MustCompile(`(?i)Redistribution and use in source and binary forms`)
	neitherRe   = regexp.MustCompile(`(?i)Neither the name|may be used to endorse`)
)

var licenseFileRe = regexp.MustCompile(`(?i)^(licen[cs]e|copying|copyright|unlicense|notice)`)

// classify maps one license text to an SPDX-ish label. The rules are ordered:
// copyleft first (fail closed), then permissive families, then public-domain
// and pure attribution files.
func classify(text string) string {
	switch {
	case copyleftRe.MatchString(text):
		return "COPYLEFT"
	case apacheRe.MatchString(text):
		return "Apache-2.0"
	case bsd2Re.MatchString(text):
		return "BSD-2-Clause"
	case bsd3Re.MatchString(text):
		return "BSD-3-Clause"
	case iscRe.MatchString(text):
		return "ISC"
	case redistribRe.MatchString(text) && neitherRe.MatchString(text):
		return "BSD-3-Clause"
	case redistribRe.MatchString(text):
		return "BSD-2-Clause"
	case mitRe.MatchString(text):
		return "MIT"
	case pdomainRe.MatchString(text):
		return "Public-Domain"
	default:
		return "Notices"
	}
}

type modInfo struct {
	path    string
	version string
	dir     string
	files   []string // license file names, sorted
	classes []string // unique detected classes, sorted
}

func run(dir string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("go %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func collect(root, self string) ([]modInfo, error) {
	out, err := run(root, "list", "-deps", "-f={{if not .Standard}}{{.Module.Path}}{{end}}", "./...")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		p := strings.TrimSpace(line)
		if p == "" || p == self {
			continue
		}
		seen[p] = true
	}
	var mods []modInfo
	for p := range seen {
		out, err := run(root, "list", "-m", "-f={{.Version}}\t{{.Dir}}", p)
		if err != nil {
			return nil, err
		}
		parts := strings.SplitN(strings.TrimSpace(out), "\t", 2)
		m := modInfo{path: p, version: parts[0], dir: strings.TrimSpace(parts[1])}
		entries, _ := os.ReadDir(m.dir)
		for _, e := range entries {
			if e.IsDir() || !licenseFileRe.MatchString(e.Name()) {
				continue
			}
			b, rerr := os.ReadFile(filepath.Join(m.dir, e.Name()))
			if rerr != nil {
				continue
			}
			m.files = append(m.files, e.Name())
			m.classes = appendUnique(m.classes, classify(string(b)))
		}
		sort.Strings(m.files)
		sort.Strings(m.classes)
		if len(m.files) == 0 {
			m.classes = []string{"Unknown"}
		}
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].path < mods[j].path })
	return mods, nil
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

var allowed = map[string]bool{
	"Apache-2.0":    true,
	"MIT":           true,
	"BSD-2-Clause":  true,
	"BSD-3-Clause":  true,
	"ISC":           true,
	"Public-Domain": true,
	"Notices":       true,
}

func writeReport(mods []modInfo, out string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Third-party licenses for KingMoat\n")
	fmt.Fprintf(&b, "Generated %s by scripts/gen-licenses (go list -deps ./...); do not edit by hand.\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	for _, m := range mods {
		fmt.Fprintf(&b, "%s\n", strings.Repeat("=", 78))
		fmt.Fprintf(&b, "%s %s\nLicense(s): %s\nFiles: %s\n", m.path, m.version, strings.Join(m.classes, ", "), strings.Join(m.files, ", "))
		fmt.Fprintf(&b, "%s\n", strings.Repeat("=", 78))
		for _, f := range m.files {
			bTxt, err := os.ReadFile(filepath.Join(m.dir, f))
			if err != nil {
				return err
			}
			fmt.Fprintf(&b, "\n--- %s/%s ---\n%s\n", m.path, f, strings.TrimRight(string(bTxt), "\n"))
		}
		b.WriteString("\n")
	}
	// Non-Go-module bundled data (static section: regenerated on every run).
	b.WriteString(strings.Repeat("=", 78) + "\n")
	b.WriteString("dbip-country-lite.mmdb (embedded DB-IP IP to Country Lite)\n" +
		"License(s): CC-BY-4.0\n" +
		"Source: https://db-ip.com\n" +
		strings.Repeat("=", 78) + "\n\n" +
		"The DB-IP IP to Country Lite database is licensed under the Creative\n" +
		"Commons Attribution 4.0 International License (CC BY 4.0).\n" +
		"Required attribution: \"IP Geolocation by DB-IP\" (https://db-ip.com).\n\n")
	return os.WriteFile(out, []byte(b.String()), 0o644)
}

func main() {
	out := flag.String("out", "THIRD-PARTY-LICENSES", "output file for the bundled licenses")
	check := flag.Bool("check", false, "verify licenses against the permissive allowlist instead of writing a file")
	root := flag.String("root", ".", "module root directory")
	flag.Parse()

	modLine, err := run(*root, "list", "-m")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-licenses:", err)
		os.Exit(1)
	}
	self := strings.TrimSpace(strings.SplitN(modLine, " ", 2)[0])

	mods, err := collect(*root, self)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-licenses:", err)
		os.Exit(1)
	}
	if len(mods) == 0 {
		fmt.Fprintln(os.Stderr, "gen-licenses: no third-party modules found")
		os.Exit(1)
	}

	if *check {
		bad := 0
		for _, m := range mods {
			for _, c := range m.classes {
				if !allowed[c] {
					fmt.Printf("VIOLATION %s %s: %s\n", m.path, m.version, c)
					bad++
				}
			}
		}
		fmt.Printf("license check: %d modules scanned, %d violations (allowlist: Apache-2.0/MIT/BSD/ISC + public-domain)\n", len(mods), bad)
		if bad > 0 {
			os.Exit(1)
		}
		return
	}

	if err := writeReport(mods, *out); err != nil {
		fmt.Fprintln(os.Stderr, "gen-licenses:", err)
		os.Exit(1)
	}
	fmt.Printf("gen-licenses: wrote %s (%d modules)\n", *out, len(mods))
}
