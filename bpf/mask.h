/*
 * mask_t — fixed-size bitmap backed by an array of __u64 words.
 * Each bit represents a rule slot; a set bit indicates the rule
 * at that slot is a candidate.
 *
 *   bits[0]     bits[1]           bits[N-1]
 *   ┌──────────┬──────────┬···┬──────────┐
 *   │ 64 bits  │ 64 bits  │   │ 64 bits  │
 *   └──────────┴──────────┴···┴──────────┘
 *   bit K = 1  →  rule at slot K is a candidate
 *
 *   Layout:  slot = group * 64 + bit
 *            group ∈ [0, N)    where N = RULE_GROUPS
 *            bit   ∈ [0, 63)
 */
#ifndef SIDERSP_BPF_MASK_H
#define SIDERSP_BPF_MASK_H

#include <linux/types.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define RULE_GROUPS 4
#define RULES_PER_GROUP 64
#define MAX_RULE_SLOTS (RULE_GROUPS * RULES_PER_GROUP)

typedef struct {
    __u64 bits[RULE_GROUPS];
} mask_t;

static __always_inline void mask_zero(mask_t *m)
{
    __u32 i;

    for (i = 0; i < RULE_GROUPS; i++)
        m->bits[i] = 0;
}

static __always_inline void mask_copy(mask_t *dst, const mask_t *src)
{
    __builtin_memcpy(dst, src, sizeof(*dst));
}

static __always_inline void mask_and(mask_t *dst, const mask_t *src)
{
    __u32 i;

    for (i = 0; i < RULE_GROUPS; i++)
        dst->bits[i] &= src->bits[i];
}

static __always_inline int mask_is_zero(const mask_t *m)
{
    __u32 i;

    for (i = 0; i < RULE_GROUPS; i++) {
        if (m->bits[i])
            return 0;
    }

    return 1;
}

static __always_inline void mask_set(mask_t *m, __u32 slot)
{
    __u32 group;
    __u32 bit;

    if (slot >= MAX_RULE_SLOTS)
        return;

    group = slot / RULES_PER_GROUP;
    bit = slot % RULES_PER_GROUP;
    m->bits[group] |= (1ULL << bit);
}

static __always_inline int mask_test(const mask_t *m, __u32 slot)
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
