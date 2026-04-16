---
name: go-coding-style
description: Use when adding or reviewing Go coding style rules. Prefer go xxx() and do not hide goroutine creation inside the called function.
---

# Go Coding Style

Use this skill when adding or reviewing Go coding style rules.

## Goroutine launch

- Prefer `go xxx()` for existing work functions
- Do not hide `go` inside the called function or method
- Keep simple wrappers inline

## Good

```go
go svc.Handle(ctx, ev)
```

## Also OK

```go
go func() {
	_ = svc.Handle(ctx, ev)
}()
```

Use this when a thin wrapper is enough.

```go
go func() {
	sig := <-sigCh
	logrus.WithField("signal", sig.String()).Info("Stopped service")
	cancel()
}()
```

## Do not

```go
func (s *Service) Handle(ctx context.Context, ev Event) {
	go s.write(ctx, ev)
}
```
