package apiasset

// TickSink consumes access observations. Implemented by *Collector.
type TickSink interface {
	Submit(t AccessTick)
}

// HitObserver receives observe-only respfilter pattern detections (R1).
type HitObserver interface {
	RespFilterHit(site, path, pattern string)
}
