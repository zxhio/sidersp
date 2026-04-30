package response

import (
	"sync/atomic"

	"sidersp/internal/model"
)

type statsCounters struct {
	responseSent     atomic.Uint64
	responseFailed   atomic.Uint64
	afxdpTX          atomic.Uint64
	afxdpTXFailed    atomic.Uint64
	afpacketTX       atomic.Uint64
	afpacketTXFailed atomic.Uint64
}

func newStatsCounters() *statsCounters {
	return &statsCounters{}
}

func (c *statsCounters) recordSent(backend TXBackend) {
	if c == nil {
		return
	}

	c.responseSent.Add(1)
	switch backend {
	case TXBackendAFXDP:
		c.afxdpTX.Add(1)
	case TXBackendAFPacket:
		c.afpacketTX.Add(1)
	}
}

func (c *statsCounters) recordFailed(backend TXBackend) {
	if c == nil {
		return
	}

	c.responseFailed.Add(1)
	switch backend {
	case TXBackendAFXDP:
		c.afxdpTXFailed.Add(1)
	case TXBackendAFPacket:
		c.afpacketTXFailed.Add(1)
	}
}

func (c *statsCounters) snapshot() model.ResponseStats {
	if c == nil {
		return model.ResponseStats{}
	}

	return model.ResponseStats{
		ResponseSent:     c.responseSent.Load(),
		ResponseFailed:   c.responseFailed.Load(),
		AFXDPTX:          c.afxdpTX.Load(),
		AFXDPTXFailed:    c.afxdpTXFailed.Load(),
		AFPacketTX:       c.afpacketTX.Load(),
		AFPacketTXFailed: c.afpacketTXFailed.Load(),
	}
}

func (c *statsCounters) reset() {
	if c == nil {
		return
	}

	c.responseSent.Store(0)
	c.responseFailed.Store(0)
	c.afxdpTX.Store(0)
	c.afxdpTXFailed.Store(0)
	c.afpacketTX.Store(0)
	c.afpacketTXFailed.Store(0)
}
