---
name: go-abstraction
description: Improve Go code structure with minimal generics, small strategy interfaces, and symmetric naming.
---

## When to use this

Use when modifying or reviewing Go code that has:

- repeated collection/store/helper logic
- long if/else or switch branches for similar business actions
- unclear type, file, method, or package names
- paired concepts such as rx/tx, read/write, start/stop, kernel/user
- growing handlers, workers, services, or managers

## Goal

Keep Go code explicit, small, and easy to extend.

Use:

- generics for structural duplication
- interfaces for behavior variation
- symmetric naming for paired roles

Do not abstract only to make code look clever.

## 1. Generics

Use generics when multiple concrete types share the same structure or algorithm.

Good use cases:

- collection helpers
- map/slice conversion
- in-memory store primitives
- cache primitives
- simple reusable algorithms
- repeated parse/validate wrappers, only when the flow is truly identical

Example:

```go
func Values[K comparable, V any](m map[K]V) []V {
    out := make([]V, 0, len(m))
    for _, v := range m {
        out = append(out, v)
    }
    return out
}
```

Rules:

- Use generics to remove real structural duplication.
- Prefer concrete types for business concepts.
- Keep constraints small and explicit.
- Do not hide business flow inside generic helpers.
- If call sites become harder to read, keep concrete code.
- Avoid generic names like Manager[T], Service[T], Handler[T] unless the boundary is very clear.

## 2. Strategy interfaces

Use interfaces when the same business action has multiple implementations.

Good use cases:

- rule action execution
- response action handling
- event sink output
- analysis backend dispatch
- config loader by type
- dataplane attach mode
- worker backend

Example:

```go
type ActionHandler interface {
    Handle(ctx context.Context, event Event) error
}

type ActionDispatcher struct {
    handlers map[ActionType]ActionHandler
}

func (d *ActionDispatcher) Dispatch(ctx context.Context, action ActionType, event Event) error {
    h, ok := d.handlers[action]
    if !ok {
        return fmt.Errorf("unsupported action: %s", action)
    }
    return h.Handle(ctx, event)
}
```

Rules:

- Use interfaces for stable extension points.
- Prefer strategy dispatch when many branches perform the same kind of action with different implementations.
- Keep the interface small, usually one main method.
- Define the interface near the caller when practical.
- Use registry or map dispatch instead of long if/else or switch chains.
- Keep simple conditions as normal if statements.
- Do not introduce interfaces for one implementation unless the boundary is expected to grow.

## 3. Symmetric naming

Use symmetric names for related roles.

Common naming axes:

- direction: Rx / Tx
- side: Kernel / User
- lifecycle: Start / Stop, Load / Unload, Attach / Detach
- data flow: Read / Write, Encode / Decode, Parse / Emit
- action: Redirect / Response / Event
- role: Reader / Writer / Handler / Dispatcher / Worker

Good examples:

```go
type XSKRxWorker struct {}
type XSKTxWorker struct {}

type KernelRedirectHandler struct {}
type UserRedirectHandler struct {}

type ResponseBuilder struct {}
type ResponseSender struct {}
```

Files:

```
xsk_rx_worker.go
xsk_tx_worker.go
kernel_redirect_handler.go
user_redirect_handler.go
response_builder.go
response_sender.go
```

Rules:

- Pick naming axes before adding or renaming types.
- Keep the same word order across related types.
- If two types are paired, their names should differ by only one axis word.
- Do not mix synonyms in the same group, such as Sender/Writer/Emitter for the same role.
- Prefer domain words over vague words like Manager, Processor, Helper, Util.
- File names should follow the same naming group when practical.

## Decision guide

Use this rule:

- Same structure, different types: consider generics.
- Same action, different implementations: consider strategy interface.
- Same concept group, different directions or sides: use symmetric naming.
- Simple condition or validation: keep normal if statements.
- Business-specific flow: prefer explicit concrete code.

## Output when reviewing code

When asked to review or plan changes, output:

### Summary

One short conclusion.

### Findings

- <duplication, branch, or naming issue>

### Suggestions

1. <suggested abstraction or naming change>
   Files: `<file>`
   Note: <why>

### Avoid

- <what should not be abstracted>

## Rules

- Prefer small, incremental changes.
- Keep behavior unchanged unless requested.
- Do not introduce abstraction without a clear call-site benefit.
- Do not combine generics and interfaces unless both are necessary.
- Preserve existing project style when it is consistent.
- Rename only when it improves symmetry or removes confusion.
- Avoid broad refactors unless directly needed.
