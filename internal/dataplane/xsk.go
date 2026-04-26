package dataplane

import (
	"errors"
	"fmt"
)

const maxXSKQueues = 64

var errXSKMapUnavailable = errors.New("xsk map is unavailable")

// RegisterXSK installs an AF_XDP socket fd for the queue used by BPF
// bpf_redirect_map(&xsks_map, queueID, ...).
func (r *Runtime) RegisterXSK(queueID int, fd uint32) error {
	if r == nil {
		return fmt.Errorf("register xsk: nil runtime")
	}
	if queueID < 0 || queueID >= maxXSKQueues {
		return fmt.Errorf("register xsk: queue %d out of range", queueID)
	}
	if r.objs.XsksMap == nil {
		return errXSKMapUnavailable
	}
	if err := r.objs.XsksMap.Put(uint32(queueID), fd); err != nil {
		return fmt.Errorf("register xsk queue %d: %w", queueID, err)
	}
	return nil
}
