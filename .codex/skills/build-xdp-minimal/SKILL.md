---
name: build-xdp-minimal
description: Build the minimal XDP dataplane for VLAN, IPv4, and TCP parsing, minimal rule matching, and minimal event export.
---

## When to use this

Use when implementing or changing the first runnable XDP dataplane prototype.

## Goal

Build the smallest useful dataplane path:

mirror traffic in -> parse minimal fields -> match minimal rules -> emit minimal event -> pass traffic

## Scope

This skill only covers the minimal dataplane prototype and its userspace event receive path.

## Inputs

- `RULES.md`
- `EVENTS.md`
- `AGENTS.md`

## Do

- Parse VLAN
- Parse IPv4
- Parse TCP
- Extract:
  - `sip`
  - `dip`
  - `sport`
  - `dport`
  - `proto`
  - `vlan`
- Match the minimal rule fields needed for the current phase
- Emit the minimal event layout defined in `EVENTS.md`
- Keep default behavior as `XDP_PASS`
- Add the smallest userspace receiver needed to print events

## Do not

- Do not add Web or API code
- Do not implement dynamic rule updates
- Do not implement complex protocol parsing
- Do not implement full response sending
- Do not add unrelated performance abstractions too early
- Do not change event layout without updating `EVENTS.md`

## Minimal matching scope

Only support the minimal rule set needed for first runnable validation:

- VLAN
- source prefixes
- destination prefixes
- source ports
- destination ports
- minimal features if already defined for the current phase

## Event constraints

Events must stay minimal and fixed-size.

Prefer integer fields and stable layout.  
Do not add display-only fields.

## Done when

- The XDP program loads
- Matching traffic emits events
- Userspace receives and prints events
- Event layout matches `EVENTS.md`
- Default packet behavior remains `XDP_PASS`