# H.264 Slice Init — Patched Code Analysis

## 1. Value Range After the Guard

The guard checks:
```c
if (h->current_slice >= 0xFFFE) {
    return AVERROR_PATCHWELCOME;
}
```

This is a **signed comparison** (`h->current_slice` is `int`, `0xFFFE` is the signed integer 65534). If the guard passes, we know:

```
h->current_slice < 65534  (i.e., < 0xFFFE)
```

Then the increment executes:
```c
sl->slice_num = ++h->current_slice;
```

So:
```
sl->slice_num < 65535  (i.e., ≤ 0xFFFE)
```

Casting to `uint16_t` for values in [0, 65534] preserves the value exactly. Therefore:

```
(uint16_t)sl->slice_num ∈ [0x0000, 0xFFFE]
```

**0xFFFF is not in this range.** The sentinel collision is impossible through the normal increment path.

---

## 2. Is the Threshold 0xFFFE Off-by-One?

**No, it is correct.**

The vulnerability occurs when `(uint16_t)sl->slice_num == 0xFFFF` (i.e., 65535). The guard blocks `h->current_slice >= 65534`, so after increment `sl->slice_num ≤ 65534 = 0xFFFE`. The maximum value castable to `uint16_t` is 0xFFFE, which is **one less than the sentinel**.

The threshold is exactly one below the collision boundary:

| `h->current_slice` | After `++` | `(uint16_t)` result | Sentinel collision? |
|---------------------|-----------|---------------------|---------------------|
| 65532 | 65533 | 0xFFDD | No |
| 65533 | 65534 | 0xFFFE | No |
| **65534** | — | — | **Blocked by guard** |
| 65535 | — | — | **Blocked by guard** |

The choice of `0xFFFE` (rather than `0xFFFF`) reflects the fact that the increment happens **after** the check. If the threshold were `0xFFFF`, then `current_slice` could reach 0xFFFF, increment to 0x10000, and wrap to 0 in `uint16_t` — which is not the sentinel, but would still be dangerous for other reasons (the `slice_row` index wrapping). The 0xFFFE threshold provides a clean cutoff.

---

## 3. Negative `int` Bypass Analysis

### The Guard Is a Signed Comparison

```c
if (h->current_slice >= 0xFFFE)  // 0xFFFE = 65534 as signed int
```

Both operands are `int`. Negative values (which are < 0) are **not** ≥ 65534, so the guard does **not** block them.

### Can a Negative `current_slice` Produce `(uint16_t)0xFFFF`?

If `current_slice == -1`:
```
++h->current_slice → 0
(uint16_t)0 → 0x0000
```
Not the sentinel.

If `current_slice == -2`:
```
++h->current_slice → -1
(uint16_t)(-1) → 0xFFFF  ← sentinel collision!
```
**Yes, this produces the sentinel.**

If `current_slice == -3`:
```
++h->current_slice → -2
(uint16_t)(-2) → 0xFFFE
```
Not the sentinel.

If `current_slice == -65537` (i.e., -0x10001):
```
++h->current_slice → -65536
(uint16_t)(-65536) → 0x0000
```
Not the sentinel.

In general, `(uint16_t)(current_slice + 1) == 0xFFFF` when `current_slice + 1 ≡ -1 (mod 65536)`, i.e., when `current_slice ≡ -2 (mod 65536)`. Concrete values: -2, -65538, -131074, etc.

### Is This Exploitable?

**No.** `h->current_slice` is a plain `int` that:
1. Starts at 0 (set during `H264Context` allocation/initialization)
2. Is only modified by `++h->current_slice` within this function
3. The guard prevents increment beyond 0xFFFE (65534)

There is no bitstream-controlled path, no user-controlled field, and no code path that sets `current_slice` to a negative value. The field is purely a counter maintained internally.

**The guard is sufficient for all reachable values.** The negative-value bypass is a theoretical unsoundness in the guard's logic (it uses `>=` rather than a range check), but it is not exploitable because no reachable execution path can make `current_slice` negative.

**Recommendation**: Consider adding a bounds check for the full reachable range to make the guard robust against future code changes that might set `current_slice` from external sources:
```c
if (h->current_slice < 0 || h->current_slice >= 0xFFFE) {
```
Or better, use an unsigned type for `current_slice` to eliminate the signed/unsigned confusion entirely.

---

## 4. Overall Verdict: Patched Code Is Safe

The patched code is **safe from the sentinel collision vulnerability**.

### Why the Patch Works

The `>= 0xFFFE` guard blocks `h->current_slice` from ever reaching the value 65534. Since the sentinel collision requires `(uint16_t)sl->slice_num == 0xFFFF` (65535), and `sl->slice_num` is at most 65534 after the increment, the sentinel value is unreachable.

### What the Patch Fixes

| Issue | Unpatched | Patched |
|-------|------|-—|
| `current_slice` can reach 65534 | Yes | Blocked by guard |
| `current_slice` can reach 65535 | Yes (after wrap) | Blocked by guard |
| `(uint16_t)sl->slice_num == 0xFFFF` | Possible | **Impossible** |
| `slice_table` sentinel collision | Possible | **Prevented** |

### Caveats

1. **Signed type**: Using `int` (signed) for `current_slice` is fragile. While not exploitable today, future code changes that set `current_slice` from external sources could introduce a negative-value bypass. Using `uint32_t` or `uint16_t` would be more robust.

2. **Integer overflow**: If `current_slice` somehow accumulates beyond `INT_MAX` (0x7FFFFFFF), signed overflow would produce undefined behavior in C. The guard at 0xFFFE would never be reached in this scenario since the value would wrap before reaching it. This is theoretically possible only if `current_slice` is never reset between frames and the decoder runs continuously for 4 billion+ slices. In practice, `current_slice` is reset to 0 at the start of each frame.

3. **Other vulnerabilities**: This patch only addresses the sentinel collision. The other vulnerabilities identified in the analysis (slice_row wraparound at MAX_SLICES, qp_thresh bounds, heap underflow) may still be present if they do not flow through `current_slice` in a way blocked by this guard.

### Conclusion

**The sentinel collision vulnerability is fully patched.** The `>= 0xFFFE` guard, combined with the post-check increment, cleanly prevents `(uint16_t)sl->slice_num` from ever reaching 0xFFFF. No bypass exists via reachable code paths. The negative-value edge case is a theoretical unsoundness but not an exploitable vulnerability.
