package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"sidersp/internal/rule"
)

const xskMetaSize = 8

var errXSKWorkerUnsupported = errors.New("xsk worker is not wired to an AF_XDP socket implementation")

// xskMeta mirrors BPF struct xsk_meta.
type xskMeta struct {
	RuleID   uint32
	Action   uint16
	Reserved uint16
}

// xskWorker owns one AF_XDP queue worker. The concrete socket backend is left
// behind this boundary so dataplane runtime does not grow response logic.
type xskWorker struct {
	ifindex  int
	queueID  int
	xsksMap  *ebpf.Map
	ruleSnap map[uint32]rule.Rule
}

func newXSKWorker(ifindex, queueID int, xsksMap *ebpf.Map, rules map[uint32]rule.Rule) *xskWorker {
	return &xskWorker{
		ifindex:  ifindex,
		queueID:  queueID,
		xsksMap:  xsksMap,
		ruleSnap: rules,
	}
}

func (w *xskWorker) Run(ctx context.Context) error {
	if w == nil {
		return fmt.Errorf("run xsk worker: nil worker")
	}

	logrus.WithFields(logrus.Fields{
		"ifindex": w.ifindex,
		"queue":   w.queueID,
	}).Info("Started xsk worker")

	<-ctx.Done()
	return ctx.Err()
}

func (w *xskWorker) RegisterSocket(fd uint32) error {
	if w == nil {
		return fmt.Errorf("register xsk socket: nil worker")
	}
	if w.xsksMap == nil {
		return errXSKWorkerUnsupported
	}
	if err := w.xsksMap.Put(uint32(w.queueID), fd); err != nil {
		return fmt.Errorf("register xsk socket queue %d: %w", w.queueID, err)
	}
	return nil
}

func decodeXSKMeta(frame []byte) (xskMeta, []byte, error) {
	if len(frame) < xskMetaSize {
		return xskMeta{}, nil, fmt.Errorf("xsk frame too short: %d", len(frame))
	}

	meta := xskMeta{
		RuleID:   binary.LittleEndian.Uint32(frame[0:4]),
		Action:   binary.LittleEndian.Uint16(frame[4:6]),
		Reserved: binary.LittleEndian.Uint16(frame[6:8]),
	}
	return meta, frame[xskMetaSize:], nil
}
