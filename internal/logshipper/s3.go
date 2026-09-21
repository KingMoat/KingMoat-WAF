package logshipper

import (
	"bytes"
	"compress/gzip"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// S3 settings for the "s3" shipper kind: MinIO, Alibaba Cloud OSS, Huawei
// Cloud OBS, AWS S3 and any other S3-compatible endpoint.
type s3Target struct {
	mc     *minio.Client
	bucket string
	prefix string
}

// newS3Target builds the minio-go client from the shipper settings. The
// endpoint may carry a scheme (https://minio.example:9000); use_ssl overrides
// the derived TLS decision when explicitly set.
func newS3Target(cfg config.ShipperSettings) (*s3Target, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("logshipper: s3 endpoint is required")
	}
	secure := true
	if u, err := url.Parse(endpoint); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		endpoint = u.Host
		secure = u.Scheme == "https"
	}
	if cfg.UseSSL != nil {
		secure = *cfg.UseSSL
	}
	mc, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("logshipper: s3 client: %w", err)
	}
	prefix := strings.Trim(cfg.Prefix, "/")
	if prefix == "" {
		prefix = "kingmoat/audit"
	}
	return &s3Target{mc: mc, bucket: cfg.Bucket, prefix: prefix}, nil
}

// checkBucket logs a warning when the bucket is missing or unreachable;
// shipping continues so a transient outage does not disable the sink.
func (t *s3Target) checkBucket(logger loggerIface) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := t.mc.BucketExists(ctx, t.bucket)
	switch {
	case err != nil:
		logger.Warn("logshipper s3: bucket check failed", "bucket", t.bucket, "err", err.Error())
	case !ok:
		logger.Warn("logshipper s3: bucket does not exist, uploads will fail until it is created", "bucket", t.bucket)
	}
}

// putBytes uploads an in-memory object under the prefix.
func (t *s3Target) putBytes(ctx context.Context, key string, data []byte, contentType string) error {
	_, err := t.mc.PutObject(ctx, t.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return fmt.Errorf("logshipper: s3 put %s: %w", key, err)
	}
	return nil
}

// pushBatch ships one batch of audit events as a gzipped NDJSON object:
// <prefix>/YYYY/MM/DD/audit-HHMMSS-<rand>.ndjson.gz
func (t *s3Target) pushBatch(batch []logstore.Event, timeout time.Duration) error {
	var buf bytes.Buffer
	for i := range batch {
		b, err := json.Marshal(batch[i])
		if err != nil {
			continue
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if buf.Len() == 0 {
		return nil
	}
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	if _, err := zw.Write(buf.Bytes()); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	now := time.Now().UTC()
	key := fmt.Sprintf("%s/%s/audit-%s.ndjson.gz",
		t.prefix, now.Format("2006/01/02"), now.Format("150405")+randSuffix())
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return t.putBytes(ctx, key, gzBuf.Bytes(), "application/gzip")
}

// uploadArchive uploads a local file (the daily DB snapshot) under
// <prefix>/archives/<name>.
func (t *s3Target) uploadArchive(localPath, objectKey string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("logshipper: open archive: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("logshipper: stat archive: %w", err)
	}
	key := path.Join(t.prefix, "archives", path.Base(objectKey))
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	_, err = t.mc.PutObject(ctx, t.bucket, key, f, st.Size(),
		minio.PutObjectOptions{ContentType: "application/gzip"})
	if err != nil {
		return fmt.Errorf("logshipper: s3 put %s: %w", key, err)
	}
	return nil
}

// randSuffix returns four random hex characters for object-name uniqueness.
func randSuffix() string {
	const hex = "0123456789abcdef"
	b := make([]byte, 4)
	_, _ = crand.Read(b)
	for i := range b {
		b[i] = hex[b[i]%16]
	}
	return string(b)
}

// loggerIface keeps s3.go decoupled from slog for the bucket check.
type loggerIface interface {
	Warn(msg string, args ...any)
}
