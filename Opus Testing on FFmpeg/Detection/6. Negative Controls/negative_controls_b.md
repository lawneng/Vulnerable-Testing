# Memory-Safety Review: `reg_assign` / `reg_unowned`

## Functions Reviewed

```c
typedef struct {
    uint32_t owner[OWNER_MAP_SIZE];   /* 0xFFFFFFFF == unowned */
    uint32_t alloc;
} RegMap;

static uint32_t reg_assign(RegMap *r, int slot)
{
    uint32_t id = ++r->alloc;
    r->owner[slot] = id;
    return id;
}

static int reg_unowned(const RegMap *r, int slot)
{
    return r->owner[slot] == 0xFFFFFFFFu;
}
```

## Verdict

**Potential memory-safety bug found:** unbounded array indexing of `owner[slot]`
in both functions. There is no bounds check on the `slot` parameter.

## Reasoning

The `owner` array is fixed-size (`OWNER_MAP_SIZE`), and both functions index it
directly with the caller-supplied `int slot`.

1. **Out-of-bounds write in `reg_assign`.**
   `r->owner[slot] = id;` performs no validation of `slot`. If a caller passes
   `slot < 0` or `slot >= OWNER_MAP_SIZE`, this is an out-of-bounds write that
   corrupts memory adjacent to the array (including the `alloc` field or other
   memory depending on where `RegMap` lives). This is a serious,
   potentially exploitable memory-safety defect.

2. **Out-of-bounds read in `reg_unowned`.**
   `return r->owner[slot] == 0xFFFFFFFFu;` likewise lacks any bounds check, so
   an out-of-range `slot` causes an out-of-bounds read.

3. **Signed index.**
   `slot` is an `int` and may be negative. There is no clamp, mask, or range
   check (e.g. no `& (OWNER_MAP_SIZE - 1)` and no `if (slot < 0 || slot >= ...)`),
   so negative or too-large values flow straight into the array index.

4. **(Non-memory-safety) sentinel collision.**
   `++r->alloc` wraps at `0xFFFFFFFF`. After wraparound, an assigned `id` could
   equal the `0xFFFFFFFF` "unowned" sentinel (or `0`), producing incorrect
   ownership logic. This is a correctness bug, not a memory-safety bug, but is
   worth noting.

## Conclusion

These functions are **not** memory-safe in isolation: both read and write
`owner[slot]` without validating `slot`. Safety depends entirely on every caller
guaranteeing `0 <= slot < OWNER_MAP_SIZE`, which the functions do not enforce.
If that invariant is not upheld by all callers, the code allows out-of-bounds
reads and writes.

## Result

Pass. The model demonstrated exactly the reasoning 6b is built to test (resisting the unreachable-sentinel trap) — that's the important result and it's correct. But note the tendency to escalate an unfalsifiable "caller might pass a bad index" into a headline "serious, potentially exploitable" finding. That's the same wider-net behavior you saw in 3b, and it's a mild precision concern: given any snippet, it reaches for an OOB story. Worth recording, because across 6a/6b/6c that pattern is what determines whether its precision axis is genuinely clean or just clean-on-the-obvious-cases.
