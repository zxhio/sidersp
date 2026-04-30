package response

import (
	"context"
	"fmt"
	"time"
)

type frameSender interface {
	SendFrame(context.Context, []byte) error
}

type ResponseExecutor struct {
	ifindex int
	queueID int
	sender  responseSender
	results *ResultBuffer
	stats   *statsCounters
}

type ResponseExecutorConfig struct {
	IfIndex int
	QueueID int
	Sender  responseSender
	Results *ResultBuffer
	Stats   *statsCounters
}

func NewResponseExecutor(config ResponseExecutorConfig) (*ResponseExecutor, error) {
	if config.QueueID < 0 {
		return nil, fmt.Errorf("create response executor: queue %d out of range", config.QueueID)
	}
	if config.Sender == nil {
		return nil, fmt.Errorf("create response executor: sender is required")
	}
	if config.Results == nil {
		return nil, fmt.Errorf("create response executor: result buffer is required")
	}
	if config.Stats == nil {
		return nil, fmt.Errorf("create response executor: stats counters are required")
	}
	return &ResponseExecutor{
		ifindex: config.IfIndex,
		queueID: config.QueueID,
		sender:  config.Sender,
		results: config.Results,
		stats:   config.Stats,
	}, nil
}

func (e *ResponseExecutor) Execute(ctx context.Context, meta XSKMetadata, frame []byte) error {
	if e == nil {
		return fmt.Errorf("execute response: nil executor")
	}

	action, ok := ResponseActionName(meta.Action)
	if !ok {
		return fmt.Errorf("execute response: unsupported action %d", meta.Action)
	}

	engine := getResponseEngine()
	defer putResponseEngine(engine)

	pkt, builder, err := engine.ResolveBuilder(meta, frame, "execute response")
	if err != nil {
		result := e.newResult(meta, action)
		engine.pkt.fillTuple(&result)
		e.recordFailure(&result, fmt.Errorf("parse response frame: %w", err))
		return err
	}

	result := e.newResult(meta, action)
	pkt.fillTuple(&result)
	if err := e.sender.Send(ctx, meta, builder, frame, pkt); err != nil {
		sendErr := fmt.Errorf("transmit response frame: %w", err)
		e.recordFailure(&result, sendErr)
		return sendErr
	}

	result.Result = ResultSent
	e.stats.recordSent(result.TXBackend)
	return e.results.recordTrusted(&result)
}

func (e *ResponseExecutor) ExecuteXSK(ctx context.Context, frame []byte) error {
	if e == nil {
		return fmt.Errorf("execute xsk frame: nil executor")
	}

	meta, payload, err := DecodeXSKMetadata(frame)
	if err != nil {
		return err
	}
	return e.Execute(ctx, meta, payload)
}

func (e *ResponseExecutor) newResult(meta XSKMetadata, action string) ResponseResult {
	return ResponseResult{
		TimestampNS: uint64(time.Now().UnixNano()),
		RuleID:      meta.RuleID,
		Action:      action,
		TXBackend:   e.sender.Backend(),
		IfIndex:     e.ifindex,
		RXQueue:     e.queueID,
	}
}

func (e *ResponseExecutor) recordFailure(result *ResponseResult, err error) {
	result.Result = ResultFailed
	result.Error = err.Error()
	e.stats.recordFailed(result.TXBackend)
	_ = e.results.recordTrusted(result)
}
