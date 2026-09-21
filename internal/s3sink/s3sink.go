// Package s3sink writes JSONL batches to S3-compatible object storage
// (MinIO / Alibaba OSS S3 endpoint / Huawei OBS S3 endpoint / AWS S3).
// Each flush produces one timestamped object: <prefix>/<kind>-<ts>-<rand>.jsonl
package s3sink

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/kingmoat/kingmoat/internal/config"
)

// Client wraps a minio client built from settings.
type Client struct {
	cli    *minio.Client
	bucket string
	prefix string
}

// New builds the client from settings.
func New(cfg *config.S3Settings) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s3: settings required")
	}
	cli, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: client: %w", err)
	}
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = "kingmoat"
	}
	return &Client{cli: cli, bucket: cfg.Bucket, prefix: prefix}, nil
}

// PutJSONL writes one JSONL batch as a timestamped object under kind/.
func (c *Client) PutJSONL(ctx context.Context, kind string, body []byte) error {
	name := fmt.Sprintf("%s/%s-%s.jsonl", c.prefix, kind,
		time.Now().UTC().Format("20060102T150405")+"-"+randHex(4))
	_, err := c.cli.PutObject(ctx, c.bucket, name, bytes.NewReader(body), int64(len(body)),
		minio.PutObjectOptions{ContentType: "application/x-ndjson"})
	return err
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
