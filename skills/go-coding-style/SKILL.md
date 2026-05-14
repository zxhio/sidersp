---
name: go-coding-style
description: Use for Go coding style and code review rules.
---

# Go Coding Style

Use this skill for local Go style and review rules, not broader abstraction design.

Keep rules short. Prefer explicit code.

## Imports

* Prefer the original package name in imports.
* Do not add aliases like `goruntime "runtime"` when `runtime` works.
* Add an alias only for a real name conflict or an established local name.

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

## Direct calls

* Prefer direct calls when they work.
* Do not add wrappers or struct fields only to avoid a direct call.
* Add indirection only for real pluggability or boundary isolation.
* If a direct call is hard to assert, test the lifecycle or result boundary instead.

## Lifecycle ownership

* Keep stop signals and blocking waits on clear boundaries.
* If `Close` only signals shutdown, keep it non-blocking.
* Let `Run` or another blocking owner wait for goroutines and close owned resources.

## Nil handling

* Do not add nil guards unless nil is a supported state.
* Let unsupported nil usage fail fast.

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

### Test scope cleanup

Keep tests that protect:

* rule semantics
* ruleset load, normalize, sort, and validation
* dataplane snapshot, apply, and rollback behavior
* BPF constants, stats, event ABI, and packet matching
* packet-path benchmarks
* meaningful failure boundaries

Prune or reduce tests that only cover:

* process start/stop smoke paths
* broad API CRUD or status-code matrices
* config schema permutations
* constructors and field assignments
* log strings
* private helper implementation details

If a low-level-looking API, config, or lifecycle test protects a real boundary,
keep the boundary and move it closer to the owning service when needed. For
example, failed rule apply must not mutate the active ruleset.

When reviewing existing tests, each remaining test should have a clear answer to
"what boundary breaks if this fails?" Delete it if the answer is only helper
formatting, default plumbing, field copying, wrapper delegation, or call count
bookkeeping. Keep it when it guards a protocol/ABI contract, packet-path behavior,
rollback behavior, resource budget, concurrency cancellation, or error
propagation boundary.

### Avoid testing

* simple constructors
* field assignments
* one-line wrappers
* private tiny helpers
* log strings
* internal call order
* unnecessary wrappers around stdlib or OS helpers
* internal setup steps such as lock/unlock thread call counts
* private runtime state polling over lifecycle boundaries

## Quick check

* Is top-level goroutine launch visible at the call site?
* If a blocking function starts goroutines internally, does it also wait for them and own their lifecycle?
* Did you avoid unnecessary wrappers?
* Are stop signals and blocking waits owned by the right method?
* Did you avoid defensive nil guards for unsupported states?
* Are raw config parsing and validated `Options` separated?
* Will the test survive refactoring if behavior stays the same?
