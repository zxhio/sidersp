package analysis

import "context"

type frameSender interface {
	SendFrame(context.Context, []byte) error
	Close() error
}
