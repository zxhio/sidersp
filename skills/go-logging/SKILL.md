---
name: logging
description: Use when adding or changing logs in Go services that should use logrus. Write short, clear, searchable logs with structured fields and stable messages.
---

# Logging

Use this skill when adding or changing logs in Go services.

Prefer `logrus` for logging.

## Structured Logging

Use:

- `WithField`
- `WithFields`
- `WithError`

Keep fields flat and stable.

Example:

```go
logrus.WithField("task_id", taskID).Info("Created task")
logrus.WithFields(logrus.Fields{
	"task_id": taskID,
	"user_id": userID,
}).Info("Started task")
logrus.WithError(err).Error("Fail to load config")
```

Do not build log context with:

- `Infof`
- `Warnf`
- `Errorf`

## Success Logs

Use:

`<Verb> + <something>`

Rules:

- start with a capitalized verb
- put the verb first
- keep it short

Example:

```go
logrus.Info("Created listener")
logrus.WithField("task_id", taskID).Info("Completed task")
```

## Failure Logs

Use:

`Fail to <verb> + <something>`

Rules:

- all failure messages start with `Fail to`
- keep the message short
- put error details in `WithError`

Example:

```go
logrus.WithError(err).Error("Fail to load config")
logrus.WithError(err).Warn("Fail to parse item")
```
