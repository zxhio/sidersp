---
name: web-console
description: Use when building lightweight frontend management pages. Keep pages simple, table-based, and free of heavy frontend architecture.
---

## When to use this

Use when implementing or changing the frontend management pages.

## Stack

- React + Vite
- Simple CSS or a light UI library only if necessary
- Put frontend code under `web/`

## Do

- use simple table-based layouts for list pages
- keep state local to each page
- call backend APIs directly from pages
- keep pages focused on display and management only

## Do not

- do not add complex state management
- do not build a large component abstraction system
- do not move backend logic into the frontend
- do not over-engineer the UI for hypothetical future needs
