package proxy

import (
	"context"
)

// tickInfo carries the request-side observation fields from Rewrite to
// ModifyResponse via the outbound request context, so the access-tick
// side-channel never touches the proxy hot path beyond a map insert.
type tickInfo struct {
	Site      string
	ClientIP  string
	UA        string
	HasAuth   bool
	TLS       bool
	BotClass  string
	QueryKeys []string
	BodyKeys  []string
}

type tickInfoKeyType struct{}

var tickInfoKey tickInfoKeyType

func withTickInfo(ctx context.Context, info *tickInfo) context.Context {
	return context.WithValue(ctx, tickInfoKey, info)
}

func tickInfoFrom(ctx context.Context) *tickInfo {
	info, _ := ctx.Value(tickInfoKey).(*tickInfo)
	return info
}

type botClassKeyType struct{}

var botClassKey botClassKeyType

type bodyKeysKeyType struct{}

var bodyKeysKey bodyKeysKeyType

func withBodyKeys(ctx context.Context, keys []string) context.Context {
	return context.WithValue(ctx, bodyKeysKey, keys)
}

func bodyKeysFrom(ctx context.Context) []string {
	keys, _ := ctx.Value(bodyKeysKey).([]string)
	return keys
}
