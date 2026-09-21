// Disk guard: watches the volume hosting the audit database and, when usage
// exceeds the high watermark, reclaims space on a strict oldest-first (FIFO)
// basis — oldest archive snapshots first, then oldest live events — until
// usage drops below the low watermark. Only the data volume participates.
package logstore

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)


// StartDiskGuard launches the watch loop; ctx cancellation stops it.
func StartDiskGuard(ctx context.Context, store *SQLiteStore, liveDir, archiveDir string, cfg *config.DiskGuardSettings, logger *slog.Logger) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	high, low := cfg.HighOrDefault(), cfg.LowOrDefault()
	iv := cfg.IntervalOrDefault()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("disk guard panic recovered", "panic", r)
			}
		}()
		ticker := time.NewTicker(iv)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			used, _, free, err := diskUsage(liveDir)
			if err != nil {
				continue
			}
			if used < float64(high) {
				continue
			}
			logger.Warn("disk guard: usage above high watermark, reclaiming",
				"used_pct", int(used), "high_pct", high, "low_pct", low, "free_bytes", free)
			reclaimed := guardReclaim(store, liveDir, archiveDir, low, logger)
			if reclaimed {
				if u2, _, _, e2 := diskUsage(liveDir); e2 == nil {
					logger.Info("disk guard: reclaim cycle finished", "used_pct", int(u2))
				}
			}
		}
	}()
}

// guardReclaim reclaims space oldest-first: (1) archive snapshots, (2) live
// events by day. Returns whether anything was removed.
func guardReclaim(store *SQLiteStore, liveDir, archiveDir string, lowPct int, logger interface {
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}) bool {
	// Phase 1: archive snapshots, oldest first.
	for {
		if used, _, _, err := diskUsage(liveDir); err != nil || used < float64(lowPct) {
			return true
		}
		oldest := oldestArchive(archiveDir)
		if oldest == "" {
			break
		}
		if err := os.Remove(oldest); err != nil {
			logger.Warn("disk guard: remove archive failed", "file", filepath.Base(oldest), "err", err)
			break
		}
		logger.Info("disk guard: archive snapshot removed (FIFO)", "file", filepath.Base(oldest))
	}

	// Phase 2: live events, oldest day first. Deleting one day per cycle
	// keeps each transaction small; the outer loop re-checks usage.
	for cycles := 0; cycles < 365; cycles++ {
		if used, _, _, err := diskUsage(liveDir); err != nil || used < float64(lowPct) {
			return true
		}
		oldestTS, ok := store.OldestEventTime()
		if !ok || oldestTS.IsZero() {
			return false
		}
		dayEnd := oldestTS.Add(24 * time.Hour)
		n, err := store.Purge(dayEnd)
		if err != nil {
			logger.Warn("disk guard: live purge failed", "err", err)
			return false
		}
		if n == 0 {
			return false // nothing older left
		}
		logger.Info("disk guard: oldest live events purged (FIFO)",
			"deleted", n, "before", dayEnd.Format(time.RFC3339))
	}
	return false
}

// oldestArchive returns the path of the oldest archive snapshot (.gz),
// sorted by name (audit-YYYYMMDD.db.gz sorts chronologically).
func oldestArchive(archiveDir string) string {
	entries, err := os.ReadDir(archiveDir)
	if err != nil || len(entries) == 0 {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".db.gz") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return filepath.Join(archiveDir, names[0])
}
