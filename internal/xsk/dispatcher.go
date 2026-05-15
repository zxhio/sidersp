package xsk

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
)

type ResponseConsumer interface {
	HandleXSK(context.Context, Envelope, Socket) error
}

type ResponseErrorRecorder interface {
	RecordXSKError(context.Context, int, error)
}

type AnalysisSubmitter interface {
	SubmitXSK(context.Context, Envelope) error
}

type Consumers struct {
	Response ResponseConsumer
	Analysis AnalysisSubmitter
}

type Dispatcher struct {
	response ResponseConsumer
	analysis AnalysisSubmitter
}

func NewDispatcher(consumers Consumers) (*Dispatcher, error) {
	if consumers.Response == nil {
		return nil, fmt.Errorf("create xsk dispatcher: response consumer is required")
	}
	return &Dispatcher{
		response: consumers.Response,
		analysis: consumers.Analysis,
	}, nil
}

func (d *Dispatcher) Dispatch(ctx context.Context, queueID int, socket Socket, frame []byte) error {
	if socket == nil {
		return fmt.Errorf("dispatch xsk frame: socket is required")
	}

	meta, payload, err := DecodeMetadata(frame)
	if err != nil {
		recordResponseError(ctx, d.response, queueID, err)
		return err
	}
	envelope := Envelope{
		QueueID:  queueID,
		Metadata: meta,
		Frame:    payload,
	}

	// Keep response on the queue-local XSK worker thread so AF_XDP socket
	// state never crosses goroutines. Analysis is submitted only after the
	// synchronous response step and must absorb any copy or queueing cost on its
	// own side path.
	responseErr := d.response.HandleXSK(ctx, envelope, socket)
	if d.analysis != nil {
		if err := d.analysis.SubmitXSK(ctx, envelope); err != nil {
			logs.App().WithFields(logrus.Fields{
				"queue":   queueID,
				"rule_id": meta.RuleID,
				"action":  meta.Action,
			}).WithError(err).Debug("Skip analysis submission")
		}
	}
	return responseErr
}

func recordResponseError(ctx context.Context, consumer ResponseConsumer, queueID int, err error) {
	recorder, ok := consumer.(ResponseErrorRecorder)
	if !ok {
		return
	}
	recorder.RecordXSKError(ctx, queueID, err)
}
