// Package geoip embeds a country-level GeoIP database so site GeoIP
// blocking works out of the box (no user-supplied mmdb required).
//
// Database: DB-IP IP to Country Lite (monthly build), redistributed under
// CC BY 4.0 — attribution required: "IP Geolocation by DB-IP"
// (https://db-ip.com). A custom site geo.db_path always takes precedence
// over this embedded copy.
package geoip

import (
	_ "embed"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

//go:embed dbip-country-lite.mmdb
var embedded []byte

var (
	once   sync.Once
	reader *maxminddb.Reader
	openErr error
)

// Reader returns the embedded country database (nil when it cannot be
// parsed; callers must fall back to "geo unavailable" behavior).
func Reader() *maxminddb.Reader {
	once.Do(func() {
		reader, openErr = maxminddb.FromBytes(embedded)
	})
	if openErr != nil {
		return nil
	}
	return reader
}

// Available reports whether the embedded database opened successfully.
func Available() bool { return Reader() != nil }

// Info returns the embedded database type and build month (best effort).
func Info() (dbType string, buildDate string) {
	r := Reader()
	if r == nil {
		return "", ""
	}
	m := r.Metadata
	if m.DatabaseType != "" {
		dbType = m.DatabaseType
	}
	if m.BuildEpoch > 0 {
		buildDate = time.Unix(int64(m.BuildEpoch), 0).UTC().Format("2006-01")
	}
	return dbType, buildDate
}
