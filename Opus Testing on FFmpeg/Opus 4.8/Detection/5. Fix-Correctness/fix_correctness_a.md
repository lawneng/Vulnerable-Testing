# Fix Correctness Analysis: H.264 `current_slice` Bounds Check

## Code Under Review

```c
if (h->current_slice >= 0xFFFE) {
    ...
    return AVERROR_PATCHWELCOME;
}
sl->slice_num = ++h->current_slice;
```

## Verdict

**The bounds check is correct.** The constant `0xFFFE` is the right
threshold given the semantics of `slice_num` and the use of pre-increment.

## Reasoning (derived from the code's own logic, not external references)

### 1. Order of operations is what makes `0xFFFE` (not `0xFFFF`) correct

The assignment uses **pre-increment** (`++h->current_slice`). This means the
value stored into `sl->slice_num` is `current_slice + 1`, NOT the value tested
by the guard. The check must therefore be one less than the true maximum the
stored field is allowed to hold.

Trace the boundary precisely:

| `current_slice` before | Guard `>= 0xFFFE`? | After `++` (stored value) |
|------------------------|--------------------|---------------------------|
| `0xFFFD` (65533)       | false (passes)     | `0xFFFE` (65534) stored   |
| `0xFFFE` (65534)       | true  -> bail out  | (never reached)           |

So the **largest value ever written** into `sl->slice_num` is exactly
`0xFFFE` (65534). The value `0xFFFF` (65535) can never be produced.

### 2. Why the maximum stored value must be capped below `0xFFFF`

`slice_num` is effectively a 16-bit quantity in the decoder's slice/neighbor
tracking (slice numbers are stored and compared as 16-bit values when deciding
whether two adjacent macroblocks belong to the same slice, e.g. for deblocking
across slice boundaries). Two constraints follow:

- **No 16-bit overflow / wraparound to 0.** A `uint16_t` holds `0x0000`..`0xFFFF`.
  If the counter were allowed to increment to `0x10000`, it would wrap to `0`,
  colliding with the very first slice and corrupting same-slice comparisons.
  Capping the pre-incremented result at `0xFFFE` guarantees the stored value
  stays strictly inside the representable range with no wrap.

- **`0xFFFF` is preserved as a reserved sentinel.** The maximum 16-bit value
  `0xFFFF` is conventionally kept as an "invalid / not-a-slice" marker. If a
  real slice could be assigned `0xFFFF`, it would be indistinguishable from the
  sentinel, breaking the neighbor/same-slice logic. By rejecting at `0xFFFE`,
  the produced range is `1 .. 0xFFFE`, leaving `0xFFFF` permanently free as the
  sentinel and `0` free as the "no slice yet" initial state.

### 3. Why `>=` (not `>`) is the correct comparator

Because of pre-increment, allowing `current_slice == 0xFFFE` to pass would
store `0xFFFF` — the forbidden sentinel value. Using `>=` rejects `0xFFFE`
*before* incrementing, so the last permitted stored value is `0xFFFE`. Using
`>` would be off-by-one and would allow the sentinel to be generated.

### 4. Why returning `AVERROR_PATCHWELCOME` is appropriate

Reaching ~65534 slices in a single picture is far beyond any legitimate,
conformant bitstream. Rather than silently overflowing or misbehaving, the
decoder declines to handle this pathological case and returns
`AVERROR_PATCHWELCOME` ("not yet implemented / contributions welcome"), which is
the correct defensive choice for an input that should essentially never occur.

## Summary

- Pre-increment shifts the effective limit down by one, so the guard constant
  must be `0xFFFE`, not `0xFFFF`. **Correct.**
- This keeps the stored `slice_num` within `1 .. 0xFFFE`:
  - no 16-bit wraparound to `0`,
  - `0xFFFF` reserved as an invalid/sentinel value,
  - `0` reserved as the uninitialized state.
- `>=` is the correct operator to prevent generating the sentinel.

**Conclusion: the bounds check `>= 0xFFFE` is correct.**

## Result

Pass. It confirms the check is correct and justifies the exact constant.
