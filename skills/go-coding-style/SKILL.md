---
name: go-coding-style
description: Use when adding or reviewing Go coding style rules, especially goroutine launch visibility, config/options boundary, and practical test scope.
---

# Go Coding Style

Use this skill for local Go coding rules, not broader abstraction design.

Keep rules short. Prefer explicit code.

## Goroutine launch

* Prefer `go xxx()` for existing work functions.
* Do not hide `go` inside non-blocking functions or methods.
* Keep simple wrappers inline.
* The call site should make top-level concurrency visible.
* Blocking orchestration functions may start child goroutines internally when they also own wait, cancel, and error propagation before return.
* Do not start background work in a function that returns before that work is done.
* For ownership, lifecycle, or abstraction design, use `go-abstraction`.

### Good

```go
go svc.Handle(ctx, ev)
```

### Also OK

```go
go func() {
    _ = svc.Handle(ctx, ev)
}()
```

### Also OK

```go
func (g *WorkerGroup) Run(ctx context.Context) error {
    var wg sync.WaitGroup
    for _, worker := range g.workers {
        worker := worker
        wg.Add(1)
        go func() {
            defer wg.Done()
            _ = worker.Run(ctx)
        }()
    }
    wg.Wait()
    return nil
}
```

### Do not

```go
func (s *Service) Handle(ctx context.Context, ev Event) {
    go s.write(ctx, ev)
}
```

## Config and options

* `config` only reads and parses raw config.
* Do not let business logic consume raw config directly.
* Convert raw config into validated module `Options` before constructing runtime components.
* Defaults, normalization, and business validation belong to module `Options`.
* Runtime checks belong to `Start`, `Run`, or the actual runtime boundary.

Recommended flow:

```
config.Load()
    ↓
module.NewOptions(cfg.Module)
    ↓
module.NewService(opt)
```

### Keep in config

* file read
* YAML / JSON parse
* env override if already used
* basic type conversion
* basic format validation

### Keep in module Options

* default values
* normalization
* business validation
* conditional required-field checks

## Tests

* Test stable behavior, not implementation details.
* Prefer boundary tests over internal helper tests.
* Do not add tests only for coverage.
* For refactors, prefer updating existing tests over adding many new ones.
* Keep tests small and focused.

### Prefer testing

* config -> Options defaults and validation
* input-to-output mapping at boundaries
* decision branching behavior
* API response format
* lifecycle boundary behavior
* error handling at important boundaries

### Avoid testing

* simple constructors
* field assignments
* one-line wrappers
* private tiny helpers
* log strings
* internal call order

## Quick check

* Is top-level goroutine launch visible at the call site?
* If a blocking function starts goroutines internally, does it also wait for them and own their lifecycle?
* Are raw config parsing and validated `Options` separated?
* Will the test survive refactoring if behavior stays the same?
