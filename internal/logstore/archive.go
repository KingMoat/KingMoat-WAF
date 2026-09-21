package logstore

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ArchiveOptions configures the daily audit-database archiver.
type ArchiveOptions struct {
	// Snapshot toggles the daily gzip snapshot of the audit database
	// (audit-YYYYMMDD.db.gz). Retention purging still runs when disabled.
	Snapshot bool
	// Dir receives the snapshots (default "<db dir>/archive").
	Dir string
	// RetentionDays deletes snapshot files older than N days
	// (<= 0 keeps them forever).
	RetentionDays int
	// PurgeDays deletes live events older than N days after archiving
	// (<= 0 never purges).
	PurgeDays int
	// UploadPrefix is the object-key prefix used when Upload is set.
	UploadPrefix string
}

// Archiver packs the audit database into a daily snapshot, enforces live
// retention and prunes old snapshot files. RunOnce is idempotent per day.
type Archiver struct {
	store  *SQLiteStore
	opts   ArchiveOptions
	logger *slog.Logger

	mu      sync.Mutex
	upload  func(localPath, objectKey string) error
	lastDay string
}

// NewArchiver creates the archiver; Run must be called to start the schedule.
func NewArchiver(store *SQLiteStore, opts ArchiveOptions, logger *slog.Logger) *Archiver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Archiver{store: store, opts: opts, logger: logger}
}

// SetUploader attaches an off-box upload hook (e.g. the S3-compatible
// shipper). Safe to call before or after Run.
func (a *Archiver) SetUploader(fn func(localPath, objectKey string) error) {
	a.mu.Lock()
	a.upload = fn
	a.mu.Unlock()
}

// Run archives on startup (catch-up for the previous day) and then whenever
// the local day changes. Blocks until ctx is cancelled.
func (a *Archiver) Run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			a.logger.Error("audit archiver panic recovered", "panic", r)
		}
	}()
	today := time.Now().Format("20060102")
	a.mu.Lock()
	a.lastDay = today
	a.mu.Unlock()
	if err := a.RunOnce(time.Now()); err != nil {
		a.logger.Warn("audit archive failed", "err", err)
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			day := now.Format("20060102")
			a.mu.Lock()
			changed := day != a.lastDay
			if changed {
				a.lastDay = day
			}
			a.mu.Unlock()
			if changed {
				if err := a.RunOnce(now); err != nil {
					a.logger.Warn("audit archive failed", "err", err)
				}
			}
		}
	}
}

// RunOnce archives yesterday's data (one gzip DB file), then applies live
// retention and prunes expired snapshot files.
func (a *Archiver) RunOnce(now time.Time) error {
	if err := os.MkdirAll(a.opts.Dir, 0o755); err != nil {
		return fmt.Errorf("logstore: archive dir: %w", err)
	}
	if a.opts.Snapshot {
		label := now.AddDate(0, 0, -1).Format("20060102")
		target := filepath.Join(a.opts.Dir, "audit-"+label+".db.gz")
		if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
			if err := a.snapshot(target); err != nil {
				return err
			}
			a.logger.Info("audit archive created", "file", filepath.Base(target))
			a.uploadSnapshot(target)
		} else if err != nil {
			return err
		}
	}
	if a.opts.PurgeDays > 0 {
		cutoff := now.AddDate(0, 0, -a.opts.PurgeDays)
		if n, err := a.store.Purge(cutoff); err != nil {
			a.logger.Warn("audit retention purge failed", "err", err)
		} else if n > 0 {
			a.logger.Info("audit retention purge applied", "deleted", n,
				"before", cutoff.Format(time.RFC3339))
		}
	}
	a.pruneSnapshots(now)
	return nil
}

func (a *Archiver) snapshot(target string) error {
	if err := a.store.Flush(3 * time.Second); err != nil {
		a.logger.Warn("audit flush before archive incomplete", "err", err)
	}
	tmp := filepath.Join(a.opts.Dir, fmt.Sprintf(".vacuum-%d.tmp.db", os.Getpid()))
	defer func() { _ = os.Remove(tmp) }()
	// VACUUM INTO produces a consistent, compacted snapshot of the live DB
	// without stopping writes.
	if _, err := a.store.db.Exec("VACUUM INTO ?", tmp); err != nil {
		return fmt.Errorf("logstore: vacuum into: %w", err)
	}
	if err := gzipFile(tmp, target); err != nil {
		return fmt.Errorf("logstore: gzip snapshot: %w", err)
	}
	return nil
}

func (a *Archiver) uploadSnapshot(target string) {
	a.mu.Lock()
	up := a.upload
	prefix := a.opts.UploadPrefix
	a.mu.Unlock()
	if up == nil {
		return
	}
	if prefix == "" {
		prefix = "archives"
	}
	key := path.Join(prefix, filepath.Base(target))
	if err := up(target, key); err != nil {
		a.logger.Warn("audit archive upload failed", "file", filepath.Base(target), "err", err)
	} else {
		a.logger.Info("audit archive uploaded", "object", key)
	}
}

func (a *Archiver) pruneSnapshots(now time.Time) {
	if a.opts.RetentionDays <= 0 {
		return
	}
	cutoff := now.AddDate(0, 0, -a.opts.RetentionDays)
	entries, err := os.ReadDir(a.opts.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "audit-") || !strings.HasSuffix(name, ".db.gz") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, "audit-"), ".db.gz")
		t, err := time.Parse("20060102", day)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			if err := os.Remove(filepath.Join(a.opts.Dir, name)); err == nil {
				a.logger.Info("audit archive pruned", "file", name)
			}
		}
	}
}

func gzipFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	zg, err := gzip.NewWriterLevel(dst, gzip.BestCompression)
	if err != nil {
		_ = dst.Close()
		return err
	}
	if _, err := io.Copy(zg, src); err != nil {
		_ = dst.Close()
		return err
	}
	if err := zg.Close(); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}
