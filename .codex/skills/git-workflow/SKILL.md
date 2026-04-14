---
name: git-workflow
description: Use for safe day-to-day Git operations in this repo, especially status checks, staging, commit preparation, and clear conventional commit messages.
---

## When to use this

Use when preparing, reviewing, and creating Git commits in this repository.

## Goal

Keep Git operations small, safe, and easy to review.

## Workflow

1. Check `git status --short`.
2. Review changes with `git diff` or `git diff --cached`.
3. Stage only relevant files.
4. Verify the repo still builds if code changed.
5. Commit with a clear message.

## Commit message format

Use Conventional Commits:

```text
<type>(<scope>): <subject>
```

Scope is optional.

## Common types

- `feat`: new feature
- `fix`: bug fix
- `docs`: documentation only
- `refactor`: code restructure without behavior change
- `test`: add or update tests
- `chore`: maintenance or repository changes
- `ci`: CI or workflow changes

## Bad examples

- `fixed stuff`
- `updates`
- `WIP`
- `misc cleanup`

## Good examples

Use a short subject for simple changes:

- `chore(repo): init minimal go repository skeleton`
- `chore(git): ignore local build artifacts`
- `feat(controlplane): add local rule loader`
- `fix(config): validate missing rules path`
- `docs(readme): clarify startup steps`

Add a body when the reason or impact is not obvious:

```text
fix(api): retry requests on 503 service unavailable

The upstream service can return 503 during traffic spikes.
Add exponential backoff with a maximum of three retries.

Closes #123
```

The body should explain:

- why the change was needed
- what behavior changed
- any important limits, risks, or follow-up context

## Rules

- Keep one commit focused on one task.
- Stage only intended files.
- Do not commit build artifacts.
- Do not use vague commit messages.
- Do not use destructive Git commands unless explicitly requested.
