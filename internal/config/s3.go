package config

import "fmt"

// S3Settings configures an S3-compatible object storage sink (MinIO,
// Alibaba OSS S3-compatible endpoint, Huawei OBS S3-compatible endpoint,
// AWS S3). Batches are written as JSONL objects under prefix.
type S3Settings struct {
	Endpoint  string `json:"endpoint"`            // e.g. "minio.internal:9000" (no scheme)
	Bucket    string `json:"bucket"`              // bucket name
	Prefix    string `json:"prefix,omitempty"`    // object key prefix, default "kingmoat"
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	UseSSL    bool   `json:"use_ssl,omitempty"` // default false (plain HTTP)
}

// Validate checks the S3 block.
func (s *S3Settings) Validate() error {
	if s == nil {
		return nil
	}
	if s.Endpoint == "" || s.Bucket == "" {
		return fmt.Errorf("s3: endpoint and bucket are required")
	}
	return nil
}
