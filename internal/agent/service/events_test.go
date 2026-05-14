package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInMemoryRuntimeSubscribeEventsReturnsNoopStream(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewEventService(runtime)

	events, err := svc.SubscribeEvents(context.Background())

	require.NoError(t, err)
	require.Nil(t, events)
}
