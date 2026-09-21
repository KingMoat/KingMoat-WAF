package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/kingmoat/kingmoat/internal/config"
)

var errRequestBodyRead = errors.New("proxy: read request body failed")

// wantsBody reports whether the request carries a body worth buffering:
// not an upgrade (WebSocket) and either a known positive Content-Length or
// a chunked body.
func wantsBody(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		strings.EqualFold(r.Header.Get("Connection"), "upgrade") {
		return false
	}
	if r.ContentLength > 0 {
		return true
	}
	if r.ContentLength < 0 { // chunked / unknown length
		return true
	}
	return false
}

// poolBufMax bounds the buffer size eligible for pooling. Requests whose
// body fits within it (the overwhelming majority) reuse pooled memory; larger
// limits fall back to plain allocations so the pool stays small.
const poolBufMax = 64 << 10

// bodyPool recycles small request-body buffers across requests. Buffers are
// reused, not zeroed — contents are always overwritten before use and never
// leave the process.
var bodyPool = sync.Pool{
	New: func() any { b := make([]byte, 0, poolBufMax); return &b },
}

// bodyBufPool wraps the pooled scratch buffer with its final cap so Put can
// decide whether the grown buffer is still worth recycling.
type bodyBufPool struct {
	buf []byte
}

// readBody reads up to limit+1 bytes of the request body. It returns the
// bytes read plus a pool handle: when pooled != nil the caller must return
// the handle via bodyPool.Put once the bytes are no longer needed (after
// inspection and forwarding decisions). over reports that the limit was
// exceeded (the extra byte was read to detect it).
func readBody(r *http.Request, limit int64) (head []byte, over bool, pooled *bodyBufPool, err error) {
	if limit > poolBufMax {
		head, err = io.ReadAll(io.LimitReader(r.Body, limit+1))
		return head, int64(len(head)) > limit, nil, err
	}

	bp := bodyPool.Get().(*[]byte)
	buf := (*bp)[:0]
	tmp := make([]byte, 16<<10)
	for {
		// Never read past limit+1: bytes beyond it must stay in the stream
		// so over-limit policies can forward them untouched.
		want := limit + 1 - int64(len(buf))
		if want <= 0 {
			break
		}
		if want > int64(len(tmp)) {
			want = int64(len(tmp))
		}
		n, rerr := r.Body.Read(tmp[:want])
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			// Glue back whatever we got so the error response is clean.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
			*bp = buf
			bodyPool.Put(bp)
			return nil, false, nil, errRequestBodyRead
		}
	}
	if int64(len(buf)) > limit {
		*bp = buf
		if cap(buf) <= poolBufMax {
			// Caller glues the bytes back before forwarding; the handle
			// must be recycled afterwards.
			return buf[:limit+1], true, &bodyBufPool{buf: buf}, nil
		}
		return buf[:limit+1], true, nil, nil
	}
	*bp = buf
	if cap(buf) <= poolBufMax {
		return buf, false, &bodyBufPool{buf: buf}, nil
	}
	return buf, false, nil, nil
}

// recycle returns a pooled handle; grown buffers beyond the pool cap are
// left to the GC.
func recycle(p *bodyBufPool) {
	if p == nil || cap(p.buf) > poolBufMax {
		return
	}
	bp := p.buf[:0]
	bodyPool.Put(&bp)
}

// bufferBody reads the request body for inspection, enforcing the site limit.
// Outcomes (pool != nil means the caller must recycle it once the bytes are
// no longer referenced — a deferred recycle in ServeHTTP covers all paths):
//   - !over          → body buffered, r.Body rewound, data returned
//   - over           → policy decides: reject (413), bypass (prefix dropped,
//     full stream forwards untouched), stream (prefix returned for
//     inspection, full stream forwards untouched)
//   - err            → client aborted or I/O failure while reading
//
// The site's WAF body limit is authoritative (proxy buffer == engine limit).
func bufferBody(r *http.Request, site *config.Site) (data []byte, over bool, pool *bodyBufPool, err error) {
	limit := site.WAF.BodyLimit()

	// Trusted Content-Length above the limit: no read at all.
	if r.ContentLength > limit {
		return nil, true, nil, nil
	}

	head, over, pool, err := readBody(r, limit)
	if err != nil {
		return nil, false, nil, err
	}
	if over {
		// Rewind consumed bytes: full stream forwards untouched (bypass and
		// stream policies), reject short-circuits before forwarding anyway.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(head), r.Body))
		if site.WAF.StreamOverLimit() {
			// Deep-inspect the buffered prefix; the remainder streams.
			return head[:limit], true, pool, nil
		}
		return nil, true, pool, nil
	}
	r.Body = io.NopCloser(bytes.NewReader(head))
	return head, false, pool, nil
}
