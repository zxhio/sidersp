---

name: go-coding-style
description: Use when adding or reviewing Go coding style rules, especially goroutine launch, config/options boundary, and practical test scope.
---

# Go Coding Style

Use this skill when adding or reviewing Go code style and small implementation rules.

Keep rules simple. Prefer explicit code over clever abstraction.

## Goroutine launch

* Prefer `go xxx()` for existing work functions.
* Do not hide `go` inside the called function or method.
* Keep simple wrappers inline.
* The call site should make concurrency visible.

### Good

```
go svc.Handle(ctx, ev)
```

### Also OK

Use this when a thin wrapper is enough.

```
go func() {
    _ = svc.Handle(ctx, ev)
}()

go func() {
    sig := <-sigCh
    logrus.WithField("signal", sig.String()).Info("Stopped service")
    cancel()
}()
```

### Do not

```
func (s *Service) Handle(ctx context.Context, ev Event) {
    go s.write(ctx, ev)
}
```

## Config and Options

* `config` only reads and parses raw config.
* Do not let business logic consume raw config directly.
* Convert raw config into validated module `Options` before constructing services, workers, or managers.
* Defaults, normalization, and business validation belong to module `Options`.
* Runtime checks belong to `Start`, `Run`, or the actual runtime boundary.

Recommended flow:

```
config.Load()
    ↓
moduleA.NewOptions(cfg.ModuleA)
moduleB.NewOptions(cfg.ModuleB)
    ↓
moduleA.NewWorker(optA)
moduleB.NewService(optB)
```

### Keep in config

* read file
* parse YAML / JSON
* env override if already used
* basic type conversion
* basic format validation

### Keep in module Options

* default values
* normalization
* business validation
* conditional required-field checks

Example:

```
func NewOptions(cfg config.ModuleConfig) (Options, error) {
    opt := Options{
        Enabled:   cfg.Enabled,
        Addr:      cfg.Addr,
        BatchSize: defaultInt(cfg.BatchSize, 64),
    }

    if opt.Enabled && opt.Addr == "" {
        return Options{}, fmt.Errorf("addr is required when module is enabled")
    }

    return opt, nil
}
```

### Do not

```
func NewWorker(cfg config.ModuleConfig) *Worker {
    batchSize := cfg.BatchSize
    if batchSize == 0 {
        batchSize = 64
    }

    return &Worker{
        batchSize: batchSize,
    }
}
```

## Tests

* Test stable behavior, not implementation details.
* Prefer boundary tests over small helper tests.
* Do not add tests only for coverage.
* For refactors, prefer updating existing tests over adding many new tests.
* Add new tests only when they protect important behavior.
* Keep tests small and focused.

### Prefer testing

* config -> Options defaults and validation
* input-to-output mapping at boundaries
* decision branching behavior
* API response format
* lifecycle boundary (start, stop, reload)
* error handling at important boundaries

### Avoid testing

* simple constructors
* field assignments
* one-line wrappers
* private tiny helpers
* log strings
* internal call order
* behavior already covered by another boundary test

Before adding a test, check:

```
Will this fail when user-visible behavior is wrong?
Will this survive internal refactoring when behavior is unchanged?
```

If not, avoid the test.

## General rules

* Keep code explicit and readable.
* Prefer existing project style.
