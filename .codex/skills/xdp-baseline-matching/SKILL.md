---
name: xdp-baseline-matching
description: Design and implement the baseline XDP rule matching pipeline for packet parsing, candidate narrowing, shallow condition detection, final rule confirmation, and minimal event emission.
---

## When to use this

Use when implementing or changing the baseline XDP rule matching pipeline in this repository.

## Goal

Build the baseline ingress matching path:

1. parse the packet in layers
2. narrow possible matching rules early
3. detect shallow conditions
4. confirm the final matching rule
5. emit a minimal event
6. return `XDP_PASS`

The focus is structure, correctness, and maintainability first.

## Scope

This skill is for the kernel-side baseline matching path.

Keep the current rule scope aligned with `RULES.md`.
Keep the event output aligned with `EVENTS.md`.

Do not extend rule fields beyond `RULES.md`.
Do not change event semantics beyond `EVENTS.md` unless the document is updated too.

## Matching pipeline

The baseline pipeline should be structured in stages:

1. packet parsing
2. candidate narrowing
3. shallow condition detection
4. final rule confirmation
5. event emission

Keep these stages explicit in the code.

## Matching strategy

Do not make the baseline path depend mainly on a complete full-rule traversal from the start.

Prefer this flow:

1. start from the enabled rule set
2. reduce the candidate set through indexed conditions
3. detect shallow packet conditions
4. confirm which remaining rules are fully satisfied
5. choose the matching rule with the smallest priority value

The baseline should reduce work before the final confirmation step, while still staying simple and easy to benchmark later.

For prefix indexes backed by LPM tries:

- do not treat the trie value as an exact-prefix-only rule set
- the lookup path may perform only one longest-prefix lookup
- therefore the stored trie value should represent the cumulative candidate set for that prefix
- shorter covering prefixes must already be merged into more specific stored entries by the index-building side

## Parsing model

Use layered parsing with clear boundaries:

- packet entry
- optional VLAN
- L3 parse
- L4 parse
- payload pointer and length setup

Use `struct pkt_ctx` as the packet parse context.

Keep these parser names in code:

- `parse_packet`
- `parse_vlan`
- `parse_arp`
- `parse_ipv4`
- `parse_ipv6`
- `parse_icmp`
- `parse_udp`
- `parse_tcp`

For the current skill guidance, focus mainly on:

- `parse_packet`
- `parse_vlan`
- `parse_ipv4`
- `parse_tcp`

The other parser functions may remain in code, but they are not the main focus of this baseline matching skill.

## Feature scope

Only support shallow, baseline-level conditions:

- VLAN present
- source port present
- destination port present
- TCP SYN
- simple HTTP method prefix checks
- simple `HTTP/1.1` detection

Do not add:

- full HTTP parsing
- header walking
- XFF extraction
- stream reassembly
- stateful protocol logic

## Rule confirmation

Separate these two concepts clearly:

- what conditions a rule requires
- what conditions the current packet satisfies

The final confirmation step must explicitly check whether the packet satisfies all conditions required by the rule.

Keep this logic easy to read and easy to audit.

## Priority handling

When multiple rules remain valid, select the rule with the smallest priority value.

Priority selection should be deterministic, visible in the code, and treat smaller values as higher priority.

## Event output

When a rule is matched:

- emit a minimal fixed-size event
- keep fields stable
- keep the structure aligned with `EVENTS.md`
- avoid display-only or debug-only payload

## Baseline design principles

- structure first
- correctness first
- bounded loops where practical
- small helpers
- concise comments
- no premature optimization

## Do

- keep parsing layered
- keep narrowing and final confirmation as separate steps
- make the final match decision explicit
- keep event emission minimal
- preserve room for later benchmark work

## Do not

- do not mix parsing and final rule decision into one large block
- do not build a deep protocol engine
- do not add response packet generation
- do not optimize too early
- do not silently drift from `RULES.md` or `EVENTS.md`

## Done when

- the XDP program has a clear staged matching pipeline
- rule scope stays aligned with `RULES.md`
- event output stays aligned with `EVENTS.md`
- candidate narrowing happens before final confirmation
- shallow conditions are detected in a dedicated step
- the matching rule with the smallest priority value is selected
- the program emits a minimal event and returns `XDP_PASS`
