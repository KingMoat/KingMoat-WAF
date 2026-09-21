// Package dynamics implements response-side dynamic protection: HTML
// responses are encrypted per request and reassembled in the browser by an
// injected decoder, so the wire format differs on every visit while the
// rendered page stays identical.
//
// The decoder uses WebCrypto (crypto.subtle), which requires a secure
// context — dynamic protection is therefore skipped on plain HTTP sites.
package dynamics

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type clientTLSKey struct{}

// WithClientSecure records whether the inbound request arrived over TLS.
func WithClientSecure(ctx context.Context, secure bool) context.Context {
	return context.WithValue(ctx, clientTLSKey{}, secure)
}

// ClientSecure reports the inbound TLS state recorded by the proxy.
func ClientSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	v, _ := r.Context().Value(clientTLSKey{}).(bool)
	return v
}

// DefaultMinBytes / DefaultMaxBytes bound the bodies we transform.
const (
	DefaultMinBytes int64 = 512
	DefaultMaxBytes int64 = 1 << 20 // 1 MiB
)

// Apply encrypts an HTML response body in place. cfg comes from the site's
// security.dynamic block. It is a no-op for non-HTML or compressed bodies.
func Apply(cfgMin, cfgMax int64, resp *http.Response) bool {
	if resp == nil || resp.Body == nil {
		return false
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return false
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return false // cannot transform a compressed stream
	}
	if !ClientSecure(resp.Request) {
		return false // WebCrypto needs a secure context (HTTPS page)
	}
	min, max := cfgMin, cfgMax
	if min <= 0 {
		min = DefaultMinBytes
	}
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if resp.ContentLength > 0 && (resp.ContentLength < min || resp.ContentLength > max) {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	resp.Body.Close()
	if err != nil || int64(len(body)) < min || int64(len(body)) > max {
		return false
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return false
	}
	aead, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(aead)
	if err != nil {
		return false
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return false
	}
	sealed := gcm.Seal(nil, nonce, body, nil)

	payload := hex.EncodeToString(nonce) + base64.StdEncoding.EncodeToString(sealed)
	html := wrapper(gcm.NonceSize(), key, payload)

	resp.Body = io.NopCloser(strings.NewReader(html))
	resp.ContentLength = int64(len(html))
	resp.Header.Set("Content-Length", fmt.Sprint(len(html)))
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Cache-Control", "no-store")
	return true
}

// wrapper builds the decoding page. Variable names are randomized per
// request to add shape variance.
func wrapper(nonceSize int, key []byte, payload string) string {
	v := func() string {
		var b [1]byte
		_, _ = rand.Read(b[:])
		return "_k" + hex.EncodeToString([]byte{b[0]})
	}
	kv, pv, ns := v(), v(), v()
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"></head><body>
<script>
var %s="%s",%s="%s",%s=%d;
(function(){
if(!(window.crypto&&crypto.subtle)){document.body.textContent="dynamic protection requires a secure context";return}
function h2a(h){var a=new Uint8Array(h.length/2);for(var i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a}
var iv=h2a(%s.slice(0,%s*2));
var raw=atob(%s.slice(%s*2));
var ct=new Uint8Array(raw.length);
for(var i=0;i<raw.length;i++)ct[i]=raw.charCodeAt(i);
crypto.subtle.importKey("raw",h2a(%s),{name:"AES-GCM"},false,["decrypt"])
.then(function(k){return crypto.subtle.decrypt({name:"AES-GCM",iv:iv},k,ct)})
.then(function(pt){document.open();document.write(new TextDecoder().decode(new Uint8Array(pt)));document.close();})
.catch(function(e){document.body.textContent="decoding failed"});
})();
</script>
</body></html>`, kv, hex.EncodeToString(key), pv, payload, ns, nonceSize, pv, ns, pv, ns, kv)
}
