/*
 * mask1024_t — 1024-bit candidate bitmap for rule matching
 *
 *   bits[0]     bits[1]          bits[15]
 *   ┌──────────┬──────────┬···┬──────────┐
 *   │ 64 bits  │ 64 bits  │   │ 64 bits  │  = 1024 bits total
 *   └──────────┴──────────┴···┴──────────┘
 *   bit N = 1  →  rule at slot N is a candidate
 *
 *   Layout:  slot = group * RULES_PER_GROUP + bit
 *            group = slot / 64   (0..15)
 *            bit   = slot % 64   (0..63)
 */
#ifndef SIDERSP_BPF_MASK1024_H
#define SIDERSP_BPF_MASK1024_H

#include <linux/types.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define RULE_GROUPS 16
#define RULES_PER_GROUP 64
#define MAX_RULE_SLOTS (RULE_GROUPS * RULES_PER_GROUP)

typedef struct {
    __u64 bits[RULE_GROUPS];
} mask1024_t;

static __always_inline void mask1024_zero(mask1024_t *m)
{
    __u32 i;

#pragma clang loop unroll(full)
    for (i = 0; i < RULE_GROUPS; i++)
        m->bits[i] = 0;
}

static __always_inline void mask1024_copy(mask1024_t *dst, const mask1024_t *src)
{
    __builtin_memcpy(dst, src, sizeof(*dst));
}

static __always_inline void mask1024_and(mask1024_t *dst, const mask1024_t *src)
{
    __u32 i;

#pragma clang loop unroll(full)
    for (i = 0; i < RULE_GROUPS; i++)
        dst->bits[i] &= src->bits[i];
}

static __always_inline int mask1024_is_zero(const mask1024_t *m)
{
    __u32 i;

#pragma clang loop unroll(full)
    for (i = 0; i < RULE_GROUPS; i++) {
        if (m->bits[i])
            return 0;
    }

    return 1;
}

static __always_inline void mask1024_set(mask1024_t *m, __u32 slot)
{
    __u32 group;
    __u32 bit;

    if (slot >= MAX_RULE_SLOTS)
        return;

    group = slot / RULES_PER_GROUP;
    bit = slot % RULES_PER_GROUP;
    m->bits[group] |= (1ULL << bit);
}

static __always_inline int mask1024_test(const mask1024_t *m, __u32 slot)
{
    __u32 group;
    __u32 bit;

    if (slot >= MAX_RULE_SLOTS)
        return 0;

    group = slot / RULES_PER_GROUP;
    bit = slot % RULES_PER_GROUP;
    return (m->bits[group] >> bit) & 1ULL;
}

#endif
