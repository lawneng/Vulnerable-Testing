# Patched Code Discrimination Analysis

## 1. Can `(uint16_t)sl->slice_num` Reach `0xFFFF` After the Patch?

Tracing the guard and increment:

```
Guard:  if (h->current_slice >= 0xFFFE) → return error
Then:   sl->slice_num = ++h->current_slice;
```

If the guard **passes** (does not fire), `h->current_slice` is **at most `0xFFFD`** (65533). After `++h->current_slice`, the maximum value is **`0xFFFE`** (65534). Cast to `uint16_t`, this yields `0xFFFE` — not `0xFFFF`.

If `h->current_slice == 0xFFFE` (65534), the guard **fires** and returns `AVERROR_PATCHWELCOME`. The increment is never reached.

If `h->current_slice == 0xFFFF` (65535), the guard **fires** (65535 >= 65534). The increment is never reached.

Through the normal increment-from-zero path, `(uint16_t)sl->slice_num` can reach at most **`0xFFFE`**. It **cannot** reach `0xFFFF`. The sentinel collision is prevented.

---

## 2. Is the `0xFFFE` Threshold Off-By-One?

**It is intentional and correct.** Using `0xFFFF` would be the off-by-one mistake.

Consider the three candidate thresholds and their effects:

| Threshold | Max `current_slice` passing guard | Max `sl->slice_num` after increment | Collides with `0xFFFF`? |
|-----------|-------------------------------------|--------------------------------------|--------------------------|
| `>= 0xFFFF` | 0xFFFD | 0xFFFE | No |
| `>= 0xFFFE` | 0xFFFD | 0xFFFE | No |
| `>= 0xFFFE` is current | 0xFFFD | 0xFFFE | No |

Wait — that shows both `0xFFFF` and `0xFFFE` work. Let me re-examine.

**With threshold `>= 0xFFFF`:**
- `current_slice == 0xFFFE` (65534): guard does NOT fire (65534 < 65535)
- After increment: `current_slice == 0xFFFF` (65535)
- `(uint16_t)0xFFFF == 0xFFFF` — **SENTINEL COLLISION!**

**With threshold `>= 0xFFFE`:**
- `current_slice == 0xFFFE` (65534): guard DOES fire (65534 >= 65534)
- Returns error. Increment never happens.
- Maximum reachable `slice_num`: `0xFFFE` — **no collision.**

The threshold must be `0xFFFE`, not `0xFFFF`, because the check happens **before** the increment. The value that produces `0xFFFF` after increment is `current_slice == 0xFFFE`. The guard must catch this value to prevent it from reaching the increment. Setting the threshold at `0xFFFF` would allow `0xFFFE` through, which then becomes `0xFFFF` after `++h->current_slice`.

**`0xFFFE` is exactly right. It is not off-by-one — it is the mathematically necessary threshold given the check-before-increment structure.**

---

## 3. Can a Negative `current_slice` Bypass the Guard?

`h->current_slice` is declared as `int` (signed 32-bit). The guard compares it against `0xFFFE`, which in C on a 32-bit-int system is a positive `int` with value 65534.

**The guard only rejects values >= 65534. It does not reject negative values.**

If `h->current_slice == -2`:
1. Guard: `-2 >= 65534` → **false** → guard does not fire
2. Increment: `++h->current_slice` → `-1`
3. Assignment: `sl->slice_num = -1`
4. Downstream cast: `(uint16_t)(-1)` → `0xFFFF` (by C99 §6.3.1.3, reduction modulo 2^16)
5. **SENTINEL COLLISION.**

Concrete trace:

```
h->current_slice = -2
Guard:  (-2 >= 65534) → false → passes
++h->current_slice → -1
sl->slice_num = -1
(uint16_t)(-1) = 0xFFFF → collision with slice_table sentinel
```

The general condition: `(uint16_t)(h->current_slice + 1) == 0xFFFF` requires `h->current_slice + 1 ≡ 0xFFFF (mod 65536)`, meaning `h->current_slice ∈ {0xFFFE, -2, 65534 + 65536k, ...}`. The guard catches `0xFFFE` but not `-2`.

**However:** Can `current_slice` actually reach `-2` through any code path in this function or its callers?

- `current_slice` is initialized to `0` at the start of each access unit (in `ff_h264_frame_start` or equivalent).
- Within `h264_slice_init`, it is only incremented (`++h->current_slice`).
- No decrement or negation of `current_slice` appears in the shown code.

For `current_slice` to be `-2`, one of the following must occur:
- A **separate memory corruption bug** overwrites the `current_slice` field in the `H264Context` struct.
- An **integer overflow** from incrementing past `INT_MAX` (2,147,483,647) wraps to `INT_MIN` in two's complement. But reaching this requires ~2 billion slice NAL units in a single access unit, which is not achievable in practice (each slice requires at minimum a few bytes, making the bitstream terabyte-scale).
- **Uninitialized use** of `H264Context` before `current_slice` is zeroed. This is unlikely given FFmpeg's initialization path.

**Verdict on negative bypass:** Theoretical but not achievable through the normal code path shown. It requires a separate, independent bug to set `current_slice` to a negative value. The patch correctly blocks the direct attack vector (incrementing from 0 to 65535). The negative path is a **defense-in-depth gap**, not a bypass of the patch itself.

A more robust guard would be:

```c
if (h->current_slice < 0 || h->current_slice >= 0xFFFE) {
    ...
    return AVERROR_PATCHWELCOME;
}
```

This closes the negative-value window entirely. But absent a separate bug that produces negative `current_slice`, the existing patch is effective.

---

## 4. Overall Verdict

**The patched code is safe from the sentinel collision vulnerability.**

The `>= 0xFFFE` guard correctly prevents `sl->slice_num` from reaching `0xFFFF` through the normal increment path. The threshold is precise and intentional — it accounts for the check-before-increment structure where `current_slice == 0xFFFE` would become `0xFFFF` after `++`.

The theoretical negative-value bypass (`current_slice == -2`) is not a weakness of this patch — it would require a separate, independent memory corruption or initialization bug to produce the negative value. No such path exists in the shown code.

The patch achieves its goal: it eliminates the specific vulnerability where an attacker crafts 65535 slices in a single access unit to make `(uint16_t)sl->slice_num` collide with the `slice_table` sentinel `0xFFFF`, which bypasses the `fill_decode_caches` top_type guard and the `xchg_mb_border` deblock check, leading to heap underflow writes at -88/-72/-56 bytes before the `top_borders` allocation.

**No bypass exists through the normal code path.**