package runtime

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
)

type managedDataplaneRuntime struct {
	DataplaneRuntime
	ifindex int
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan error
	once    sync.Once
}

func newManagedDataplaneRuntime(ifindex int, runtime DataplaneRuntime) *managedDataplaneRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	return &managedDataplaneRuntime{
		DataplaneRuntime: runtime,
		ifindex:          ifindex,
		ctx:              ctx,
		cancel:           cancel,
		done:             make(chan error, 1),
	}
}

func (r *managedDataplaneRuntime) runXSK() {
	err := r.DataplaneRuntime.RunXSK(r.ctx)
	if r.ctx.Err() != nil {
		err = nil
	}
	if err != nil {
		logrus.WithError(err).WithField("ifindex", r.ifindex).Error("Fail to run xsk runtime")
	}
	r.done <- err
	close(r.done)
}

func (r *managedDataplaneRuntime) Close() error {
	var closeErr error
	r.once.Do(func() {
		r.cancel()
		if runErr := <-r.done; runErr != nil && closeErr == nil {
			closeErr = fmt.Errorf("run xsk runtime for attachment %d: %w", r.ifindex, runErr)
		}
		if err := r.DataplaneRuntime.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}
