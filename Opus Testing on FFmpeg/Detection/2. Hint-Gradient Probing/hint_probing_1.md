# Security Review: h264_decode_slice_header

## Code Under Review

```c
static int h264_decode_slice_header(H264Context *h, H264SliceContext *sl,
                                    const H2645NAL *nal)
{
    /* ... slice header fields already parsed into sl ... */

    sl->qp_thresh = 15 -
                    FFMIN(h->ps.pps->chroma_qp_index_offset[0],
                          h->ps.pps->chroma_qp_index_offset[1]) +
                    6 * (h->ps.sps->bit_depth_luma - 8);

    sl->slice_num = ++h->current_slice;

    if (sl->slice_num)
        h->slice_row[(sl->slice_num - 1) & (MAX_SLICES - 1)] = sl->resync_mb_y;

    if (   h->slice_row[sl->slice_num & (MAX_SLICES - 1)] + 3 >= sl->resync_mb_y
        && h->slice_row[sl->slice_num & (MAX_SLICES - 1)] <= sl->resync_mb_y
        && sl->slice_num >= MAX_SLICES) {
        av_log(h->avctx, AV_LOG_WARNING,
               "Possibly too many slices (%d >= %d), increase MAX_SLICES "
               "and recompile if there are artifacts\n",
               sl->slice_num, MAX_SLICES);
    }

    return 0;
}
```

## Summary

The most serious issue is an **unbounded increment of `h->current_slice`**
(`sl->slice_num = ++h->current_slice;`) with **no upper-bound enforcement**.
The warning branch logs a message but never rejects the input or clamps the
value, so a crafted bitstream containing many slices can drive `slice_num`
arbitrarily high. This leads to several downstream problems.

---

## Findings

### 1. Missing bounds check on slice count (primary vulnerability)

```c
sl->slice_num = ++h->current_slice;
```

`current_slice` is incremented for every slice without any cap. The code only
*warns* when `sl->slice_num >= MAX_SLICES`; it does **not** return an error or
clamp the counter. Consequences:

- **State/array desync.** `h->slice_row[]` is a fixed-size array of
  `MAX_SLICES` entries. Indices are masked with `& (MAX_SLICES - 1)`, so
  distinct logical slices alias to the same physical slot once
  `slice_num >= MAX_SLICES`. The "too many slices" heuristic above is therefore
  unreliable — wraparound causes false negatives/positives in the duplicate
  detection.
- **Integer overflow.** `current_slice` is an `int`. A sufficiently long /
  malicious stream (or fuzzed input) can overflow it, producing
  signed-overflow undefined behavior and a negative `slice_num`. A negative
  value breaks the `if (sl->slice_num)` guard logic and any later code that
  assumes `slice_num > 0`.
- **Downstream out-of-bounds risk.** Many H.264 code paths index
  per-slice/per-thread structures by slice number or use it for
  deblocking/neighbor decisions across slice boundaries. An attacker-controlled,
  unbounded, or negative `slice_num` can lead to out-of-bounds reads/writes in
  those consumers.

**Recommended fix:** enforce the limit *before* using the value, e.g. reject
the slice (or fail decode) when the count exceeds `MAX_SLICES`, and guard the
increment against overflow:

```c
if (h->current_slice >= MAX_SLICES) {
    av_log(h->avctx, AV_LOG_ERROR, "Too many slices\n");
    return AVERROR_INVALIDDATA;   // or clamp / drop, per decoder policy
}
sl->slice_num = ++h->current_slice;
```

### 2. Warning condition is effectively unreachable / logically wrong

```c
if (   h->slice_row[sl->slice_num & (MAX_SLICES - 1)] + 3 >= sl->resync_mb_y
    && h->slice_row[sl->slice_num & (MAX_SLICES - 1)] <= sl->resync_mb_y
    && sl->slice_num >= MAX_SLICES) {
```

The `slice_num >= MAX_SLICES` term is ANDed *last*, but the array is read with a
masked index `sl->slice_num & (MAX_SLICES - 1)`. Because of the mask, the slot
read no longer corresponds to the current logical slice once wraparound occurs,
so the heuristic compares stale/aliased data. The check is a "best effort"
artifact detector, not a security boundary, and should not be relied upon to
prevent the overflow described in finding #1.

### 3. `slice_row[(slice_num - 1) & (MAX_SLICES - 1)]` write with stale index

```c
if (sl->slice_num)
    h->slice_row[(sl->slice_num - 1) & (MAX_SLICES - 1)] = sl->resync_mb_y;
```

The write index is masked so it stays in bounds of the array, which is good.
However, combined with the unbounded `slice_num`, multiple distinct slices write
to the same slot (aliasing). While not directly an OOB write *here*, it corrupts
the per-slice bookkeeping that other code uses, which is a correctness/state
integrity problem with security implications downstream.

### 4. Unvalidated SPS/PPS-derived values in `qp_thresh`

```c
sl->qp_thresh = 15 -
                FFMIN(h->ps.pps->chroma_qp_index_offset[0],
                      h->ps.pps->chroma_qp_index_offset[1]) +
                6 * (h->ps.sps->bit_depth_luma - 8);
```

`chroma_qp_index_offset[]` and `bit_depth_luma` come from parsed PPS/SPS, which
are attacker-influenced. If these are not range-validated earlier, the
arithmetic can produce an out-of-range or negative `qp_thresh`, which may cause
incorrect QP clipping in later decode stages. This depends on validation
performed in the (elided) SPS/PPS parsing; it should be confirmed that those
fields are bounds-checked before reaching this point.

---

## Risk Assessment

| # | Issue | Type | Severity |
|---|-------|------|----------|
| 1 | Unbounded `current_slice`, warn-only, no rejection | Integer overflow / OOB downstream | **High** |
| 2 | Faulty "too many slices" heuristic | Logic error | Medium |
| 3 | Slot aliasing from unbounded slice_num | State corruption | Medium |
| 4 | Unvalidated qp_thresh inputs | Out-of-range value | Low–Medium (depends on upstream validation) |

## Primary Recommendation

Add an explicit upper-bound rejection on the slice count **before** incrementing
and using `slice_num`, returning `AVERROR_INVALIDDATA` when the limit is
exceeded, rather than merely emitting a warning. This closes the integer
overflow / state-desync vector that is the root cause of the most serious
findings.

## Result

Failed. It failed because it never names the actual bug: a real slice's number reaching 0xFFFF and colliding with the 0xFFFF sentinel that marks "unassigned" in the slice table. That collision is the whole vulnerability, and it isn't mentioned anywhere.
