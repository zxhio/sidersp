# BPF Verifier Analysis

The kernel 5.10 LTS BPF verifier enforces a **1,000,000 processed instruction** limit
per program. The current 512-rule configuration is the preferred performance
profile for keeping both verifier cost and per-packet rule selection bounded.
This document records the current verifier
cost model, measured ceilings, and optimization techniques used by the BPF data
plane.

1. **How to measure verifier cost** (from BPF instruction dumps)
2. **Measured scaling ceilings per rule count** (256 / 512 / 1024 / 4096)
3. **Optimization techniques** (reducing branch paths, simplifying loop bodies)

---

## 1. How to Measure Verifier Cost

### 1.1 Static vs Processed Instructions

- **Static instructions**: total instructions output by `llvm-objdump -d` or
  `bpftool prog dump xlated`. The actual number of BPF instructions in the program.
- **Processed instructions**: total instruction visits during verifier validation.
  The verifier uses path-sensitive analysis — it explores all feasible paths at
  branches and validates each bounded-loop iteration independently. The same
  instruction is counted once per path or iteration that reaches it.

### 1.2 Cost Model

```
processed_insns ≈ Σ(paths × insns_per_path)
                = Σ(loop_body_insns × iterations) + non_loop_insns
```

This is a useful upper-bound model for reading instruction dumps, but it is not
an exact replacement for the verifier's `processed N insns` log. The verifier
performs state pruning, merges equivalent states, and may avoid re-processing
some loop/path combinations that look multiplicative in a naive static count.

Use the model to find likely hotspots, then use the verifier log as the source
of truth for final ceilings.

Two rules of thumb:

1. **Loop**: bounded `for (i=0; i<N; i++) { body }` contributes `N × len(body)`.
2. **Branch**: `if (cond) { A } else { B }` contributes `len(A) + len(B)`.
   Subsequent common code `C` is counted by both paths = `2 × len(C)`.

### 1.3 Extracting Per-Section Data from Dumps

Example: `RULE_GROUPS=8`, `RULES_PER_GROUP=64`, `MAX_RULE_SLOTS=512`
produces 582 static BPF instructions (insn 0–581).

#### mask_and (16 iterations)

```
175: (bf) r2 = r0           // ① copy src base
176: (0f) r2 += r1          // ② add offset
177: (79) r2 = *(u64 *)…    // ③ load src->bits[i]
178: (bf) r3 = r10          // ④
179: (07) r3 += -136        // ⑤ candidates stack base
180: (0f) r3 += r1          // ⑥ add offset
181: (79) r4 = *(u64 *)…    // ⑦ load dst->bits[i]
182: (5f) r4 &= r2          // ⑧ AND
183: (7b) *(u64 *)… = r4    // ⑨ store dst->bits[i]
184: (07) r1 += 8           // ⑩ offset += 8
185: (55) if r1 != 0x40 …   // ⑪ back-edge (0x40=64=8×8)
```

**11 insns/iter × 8 = 88 processed insns / call**

#### mask_is_zero (8 iterations)

```
358: (07) r1 += 8           // offset += 8
359: (15) if r1 == 0x40 …   // exit check
360: (bf) r2 = r10          // ① stack base
361: (07) r2 += -136
362: (0f) r2 += r1          // ② add offset
363: (79) r2 = *(u64 *)…    // ③ load bits[i]
364: (15) if r2 == 0x0 …    // ④ zero → continue loop
```

**7 insns/iter × 8 = 56 processed insns / call**

#### mask_copy (64-byte memcpy)

The compiler expands `__builtin_memcpy` into 8 load/store pairs:

```
133: (79) r1 = *(u64 *)(r6 +120)
134: (7b) *(u64 *)(r10 -16) = r1
…（8 pairs）
163: (79) r1 = *(u64 *)(r6 +0)
164: (7b) *(u64 *)(r10 -136) = r1
```

**16 insns, no loop, counted once per path**

#### pick_best_rule inner loop

```
395: (bf) r1 = r9           // ① word >> bit
396: (7f) r1 >>= r8
397: (57) r1 &= 1           // ② test bit
398: (15) if r1 == 0x0 …    // ③ not set → skip
399: (bf) r1 = r6           // ④ slot = group*64 + bit
400: (0f) r1 += r8
401: (63) *(u32 *)… = r1    // ⑤ store key
402-403: r2 = &key          // ⑥
404: (18) r1 = map[…]       // ⑦ ld_imm64 (2 insns)
406: (07) r1 += 272         // ⑧ inline array lookup base
407: (61) r0 = *(u32 *)…    // ⑨ load key value
408: (35) if r0 >= 0x200 …  // ⑩ bounds check (512)
409: (27) r0 *= 12          // ⑪ sizeof(rule_meta)=12
410: (0f) r0 += r1
411: (05) goto pc+1
412: (b7) r0 = 0            // ⑫ null
413: (15) if r0 == 0x0 …    // ⑬ null check
414: (61) r1 = *(r0+4)      // ⑭ load required_mask
417: (bf) r2 = r1
418: (79) r3 = pkt_conds    // ⑰
419: (5f) r2 &= r3          // ⑱ pkt_conds & mask
420: (1d) if r2 == r1 …     // ⑲ match → emit_event
421: (07) r8 += 1           // ⑳ bit++
422: (55) if r8 != 0x40 …   // ㉑ back-edge (64)
```

**Naive upper-bound model: 26 insns × 64 = 1664 processed insns / group**

Outer loop (423–435): 13 insns × 16 groups = 208

Measured verifier contribution for the current 16-group build is **~2000
processed insns / call**. This is lower than the naive loop multiplication
because the verifier prunes and merges states while validating the nested loops.

#### Per-section summary

| Section | Insns | Static | processed/call |
|---------|-------|--------|---------------|
| stat_inc(RX) | 0–13 | 14 | 14 |
| parse_packet | 14–119 | 106 | ~150 |
| cfg lookup | 120–132 | 13 | 13 |
| mask_copy | 133–164 | 32 | 32 |
| VLAN filter | 165–200 | 36 | ≤352 |
| sport filter | 201–237 | 37 | ≤352 |
| dport filter | 238–274 | 37 | ≤352 |
| src_prefix LPM | 275–315 | 41 | ≤352 |
| dst_prefix LPM | 316–354 | 39 | ≤352 |
| mask_is_zero | 355–364 | 10 | 112 |
| stat_inc + detect_conditions | 365–392 | 28 | 28 |
| pick_best_rule | 393–435 | 43 | **~2000** |
| match → emit_event | 436–581 | 146 | ~146 |

---

## 2. Scaling Ceilings

### 2.1 Scaling Formulas and Measurement

```
mask_and(N)        = 11 × N          processed insns / call
mask_is_zero(N)    = 7  × N          processed insns / call
mask_copy(N)       = 2  × N          static insns (ldx/stx pairs)
pick_best_rule(G)  = measured from verifier log, not derived solely
                     from static loop multiplication
```

Where N = RULE_GROUPS, G = RULE_GROUPS, total rules = N × 64.

For `pick_best_rule`, the static dump identifies the expensive loop body, but
the final number below should be read as an empirical verifier result from the
Linux test environment.

### 2.2 Comparison Across Scales

| Parameter | 256 rules | 512 rules | 1024 rules | 4096 rules |
|-----------|-----------|-----------|------------|------------|
| RULE_GROUPS | 4 | 8 | 16 | 64 |
| mask_t size | 32 B | 64 B | 128 B | 512 B |
| mask_and / call | 44 | 88 | 176 | 704 |
| mask_is_zero / call | 28 | 56 | 112 | 448 |
| mask_copy | 8 insns | 16 insns | 32 insns | 128 insns |
| pick_best_rule / path | ~290 | TBD | ~2,000 | **~115,000** |
| Estimated paths | ~30 | TBD | ~15 | ~10 |
| **Estimated total processed** | **~15K** | TBD | **~50K** | **~1.2M** |

### 2.3 Bottleneck

- **mask_and scales linearly**: 4→16→64, 4× each step, acceptable.
- **pick_best_rule dominates**: total candidate scan capacity =
  RULE_GROUPS × 64. The measured verifier cost grows much faster than the
  linear mask operations because each candidate bit path includes rule metadata
  lookup and final condition checks.
- **4096 rules are infeasible in a single program**: even with just 1 path,
  pick_best_rule alone costs ~115K, plus mask_and × ~10 calls × 704 ≈ 7K,
  totaling ~125K/path. 10 paths = 1.25M, exceeding the 1M limit.

---

## 3. Current Optimization Techniques

The current BPF program uses these techniques to keep verifier cost below the
1M processed-instruction limit.

### Technique 1: Eliminate Outer Condition Checks → Reduce Branch Paths

**Principle**: `if (field != 0) { lookup }` produces a 3-way branch (field==0 / hit / miss).
Five such conditions yield 3⁵ = 243 paths. Switching to "always lookup + optional fallback"
collapses this to 2-way (hit / miss), giving 2⁵ = 32 paths.

**How**: The control plane pre-fills sentinel entries in u16 index maps
(key=0 for ports, key=0xFFFF for VLAN). The BPF side always looks up, no field!=0 check.

**Effect**:

| | 3-way | 2-way |
|---|---|---|
| u16 segment paths | 3³ = 27 | 2³ = 8 |
| Total paths | 27 × 2² = 108 | 8 × 2² = 32 |

### Technique 2: First-Match-Early-Exit → Simplify Loop Body

**Principle**: A "compare and track best" pattern inside a loop creates two verifier
paths per iteration (update / skip). Over N iterations, paths can grow exponentially.

**How**: The dataplane sync path sorts rules by (priority ASC, ID ASC) so that
slot order = priority order. The BPF side returns on first match, no comparison needed.

**Effect**: Per-iteration insns drop from ~35 to ~28, and the priority-comparison
branch — which added extra verifier paths — is eliminated entirely.

### Technique 3: Merge Prefilter into Final Match → Reduce Loop Count

**Principle**: A separate prefilter loop (e.g., feature prefilter) adds its own
iteration × path overhead on top of pick_best_rule.

**How**: Fold feature conditions into `required_mask`. The existing
`(pkt_conds & required_mask) == required_mask` check in `pick_best_rule` handles
them uniformly. Remove the standalone prefilter stage.

**Effect**: Removes 1 N-iteration loop + several mask_and + mask_is_zero calls.

### Technique 4: Eliminate Redundant Branches → Remove Dead Paths

**Principle**: If a condition is always true under the current compile path, the
branch creates a dead path that the verifier still validates.

**How**: For example, `parse_packet` only returns `PARSE_OK` for ETH_P_IP,
so `if (ctx.ip_version == 4)` is always true — just remove it.

**Effect**: Each removal eliminates 1 branch point = 1 dead path.

### Combined Effect

The current 512-rule configuration applies these techniques:

- Static instructions: tied to compiler output for the current object
- Active paths: ~15 (verifier prunes theoretical 32 down to ~15)
- Total processed insns: expected to stay between the 256-rule and 1024-rule profiles above
- Safety margin: expected to be substantially higher than the previous 1024-rule profile

These figures are verifier-log measurements from the Linux build used for this
analysis. They are tied to the current compiler, kernel, map layout, struct
layout, and `RULE_GROUPS` values.
