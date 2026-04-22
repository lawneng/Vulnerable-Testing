# Patched `h264_slice_init` — Sentinel Collision Vulnerability Assessment

## 1. Value Range of `h->current_slice` After the Guard

The guard executes the check **before** the increment:

```c
if (h->current_slice >= 0xFFFE) {   // check
    return AVERROR_PATCHWELCOME;     // reject
}
sl->slice_num = ++h->current_slice;  // increment after check
```

Trace the possible execution paths:

| `h->current_slice` before check | Check result | Value after `++` | `(uint16_t)` cast |
|--------------------------------|-------------|-------------------|-------------------|
| 0xFFFD | passes (0xFFFD < 0xFFFE) | 0xFFFE | 0xFFFE |
| 0xFFFE | **fails** (0xFFFE >= 0xFFFE) | — (rejected) | — |
| 0xFFFF | **fails** | — | — |

The maximum value `h->current_slice` can reach after the increment is **0xFFFE**. As a `uint16_t`, this is `0xFFFE` — not `0xFFFF`.

**Conclusion: `(uint16_t)sl->slice_num` can never equal `0xFFFF` through the normal increment path. The sentinel collision is blocked.**

---

## 2. Is the `0xFFFE` Threshold Correct or Off-By-One?

The threshold is **correct and intentional**. Here is why:

The guard must prevent `h->current_slice` from reaching any value whose `uint16_t` representation is `0xFFFF`. The increment happens *after* the check, so the check must gate the value *before* it is incremented.

- If the check were `>= 0xFFFF`: the value 0xFFFE would pass, increment to 0xFFFF, and `sl->slice_num == 0xFFFF` — **sentinel collision achieved, patch defeated.**
- If the check were `>= 0xFFFE`: the value 0xFFFE is rejected, so the maximum reachable value after increment is 0xFFFE — **safe.**

The `0xFFFE` threshold is the tightest correct bound. Using `0xFFFF` would be the off-by-one error (fencepost), allowing exactly the collision the patch intends to prevent.

---

## 3. Signed Integer Bypass: Can a Negative `current_slice` Produce `0xFFFF`?

`h->current_slice` is `int` (signed 32-bit). The guard `h->current_slice >= 0xFFFE` compares against a signed integer. A negative value is **less than** `0xFFFE`, so it passes the guard.

After passing, `++h->current_slice` increments the negative value. When the result is later stored in `h->slice_table` (a `uint16_t` array), the cast `(uint16_t)sl->slice_num` applies C's implementation-defined conversion for negative values to unsigned. On every mainstream platform (two's complement), this truncates to the low 16 bits.

**Can a negative `int` cast to `uint16_t` equal `0xFFFF`?**

Yes. `(uint16_t)(-1) == 0xFFFF`. More generally, any `int` value whose low 16 bits are all 1s produces `0xFFFF`:
- `-1` = `0xFFFFFFFF` → `0xFFFF`
- `-65537` = `0xFFFEFFFF` → `0xFFFF`
- `65535` = `0x0000FFFF` → `0xFFFF` (but this is blocked by the guard)
- `131071` = `0x0001FFFF` → `0xFFFF` (blocked: 131071 >= 0xFFFE)

**The question is: can `h->current_slice` become negative?**

`h->current_slice` starts at 0 and is only ever incremented in this function (`++h->current_slice`). It is reset to 0 at the start of each frame (in `h264_field_start`). Under normal operation, it is always non-negative.

However, consider these scenarios:

**Scenario A — Integer overflow of `h->current_slice`:**
After 2^31 increments (INT_MAX + 1), `h->current_slice` wraps from `0x7FFFFFFF` to `0x80000000` (INT_MIN = -2147483648) — this is undefined behavior in C, but on two's complement platforms, it wraps to a negative value. The guard `h->current_slice >= 0xFFFE` would be **false** for any negative value, so the increment continues.

But reaching INT_MAX + 1 requires ~2.1 billion slices, which is not practical within a single frame (even 65,536 slices already requires extreme bitstreams).

**Scenario B — `current_slice` not reset between frames:**
If a code path exists where `h264_field_start` is skipped (e.g., error recovery, edge-case stream structure), `h->current_slice` could accumulate across frames. Over many frames, it could eventually reach a value whose `uint16_t` truncation is `0xFFFF`.

But in the normal path, `h->current_slice` is reset to 0 per frame. And even if not reset, after incrementing from 0, the first value whose `uint16_t` is `0xFFFF` is 65535 — which is blocked by the guard.

**Scenario C — Attacker-controlled initial value:**
If an attacker can set `h->current_slice` to a negative value through a separate vulnerability or uninitialized memory, they bypass the guard trivially. But this requires a separate bug.

**Verdict on signed bypass:** The guard as written does not protect against negative `current_slice` values. However, there is no practical code path in FFmpeg where `current_slice` becomes negative through normal operation. The integer overflow path requires ~2 billion slices, which is far beyond the 65,535-slice practical limit already established. The signed bypass is **theoretically present but not practically exploitable** without a second bug.

---

## 4. Overall Verdict

**The patch is safe against the sentinel collision vulnerability described in the original analysis.**

| Attack path | Blocked? | Reason |
|-------------|----------|--------|
| Normal increment to 65,535 → `0xFFFF` | **Yes** | Guard at `0xFFFE` prevents `current_slice` from reaching 65,535 |
| Off-by-one at threshold | **No** | `0xFFFE` is the correct fencepost; `0xFFFF` would be the error |
| Negative `current_slice` → `(uint16_t)(-1) == 0xFFFF` | **Theoretically no, practically yes** | Requires ~2^31 slices for overflow or a separate bug to set a negative initial value |
| `MAX_SLICES` masked index collision in `ref2frm`/`slice_row` | **No** | The patch does not address this secondary issue; slices 129+ still overwrite earlier entries |

**Remaining concerns (not sentinel collision, but related):**

1. **`ref2frm`/`slice_row` index collision:** The masked index `sl->slice_num & (MAX_SLICES - 1)` still wraps at `MAX_SLICES` (128). Slices 129+ silently overwrite data from earlier slices. This is not fixed by the sentinel guard and remains a potential stale-data vulnerability, though it is lower severity than the sentinel collision (it causes incorrect reference frame mapping rather than a direct memory safety violation).

2. **Signed `current_slice`:** The guard compares `h->current_slice >= 0xFFFE` where `0xFFFE` is an `int` literal. If `current_slice` were ever negative, the comparison would pass. A defensive improvement would be to also check `h->current_slice < 0` or to declare `current_slice` as `unsigned int`. This is a hardening opportunity, not a live vulnerability.

3. **Error code:** The patch uses `AVERROR_PATCHWELCOME` rather than `AVERROR_INVALIDDATA`. This is semantically less precise (the input is invalid, not merely unsupported) but functionally equivalent for security — both cause the function to return an error before the increment.

**Bottom line: The `0xFFFE` guard correctly prevents `(uint16_t)sl->slice_num == 0xFFFF` through the direct increment path, which is the exploitable vector identified in the original vulnerability. The patch is effective.**