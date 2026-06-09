# Security & Bug Review: `h264_decode_slice_header`

## Function Under Review

```c
static int h264_decode_slice_header(H264Context *h, H264SliceContext *sl,
                                    const H2645NAL *nal)
{
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

---

## Summary

The most serious concrete bug in this function is the **incorrect evaluation
order of the "too many slices" detection condition**, combined with reliance on
`++h->current_slice` as a slice counter that is never bounds-checked here. While
the `& (MAX_SLICES - 1)` mask prevents an out-of-bounds array access on
`slice_row[]`, the heuristic that is supposed to warn about slice-count overflow
is effectively broken, and there are several latent correctness/robustness
problems worth flagging.

---

## Findings

### 1. Logic bug: short-circuit ordering defeats the overflow guard (Primary)

The condition that detects "too many slices" is:

```c
if (   h->slice_row[sl->slice_num & (MAX_SLICES - 1)] + 3 >= sl->resync_mb_y
    && h->slice_row[sl->slice_num & (MAX_SLICES - 1)] <= sl->resync_mb_y
    && sl->slice_num >= MAX_SLICES)
```

The cheap, definitive guard — `sl->slice_num >= MAX_SLICES` — is evaluated
**last**. The two leading sub-conditions read `slice_row[...]` and compare it
against `resync_mb_y`. For `sl->slice_num < MAX_SLICES` (the common case),
those two reads are pointless work, and more importantly the whole construct
relies on the masked index aliasing to two **different physical slots**:

- Write slot:  `(sl->slice_num - 1) & (MAX_SLICES - 1)`
- Read slot:   `(sl->slice_num)     & (MAX_SLICES - 1)`

Because the write uses `slice_num - 1` and the read uses `slice_num`, the code
is reading a slot belonging to a *different* slice index. This is intentional in
the upstream heuristic (it is trying to detect when the ring buffer has wrapped
and a previously-stored row collides), but the ordering means the guard
`slice_num >= MAX_SLICES` no longer short-circuits the array reads. The reads
happen unconditionally on every slice, defeating the intent and making the
warning fire on patterns that are *not* actually overflow once wrapping occurs.

**Impact:** The diagnostic is unreliable — it can both miss real
too-many-slices conditions and emit spurious warnings. Reorder so the
counter test gates the array reads:

```c
if (   sl->slice_num >= MAX_SLICES
    && h->slice_row[sl->slice_num & (MAX_SLICES - 1)] + 3 >= sl->resync_mb_y
    && h->slice_row[sl->slice_num & (MAX_SLICES - 1)] <= sl->resync_mb_y)
```

---

### 2. Unbounded `h->current_slice` increment / integer overflow

```c
sl->slice_num = ++h->current_slice;
```

`h->current_slice` is incremented for every slice header processed and is
**never reset or clamped inside this function**. A crafted stream containing a
very large number of slices/NALs can drive this counter arbitrarily high.

- If `slice_num` is a signed `int`, sustained increments are **signed integer
  overflow → undefined behavior**. After overflow it can become negative.
- A negative `slice_num` makes `if (sl->slice_num)` true while
  `sl->slice_num - 1` underflows further, and the masked index
  `(sl->slice_num - 1) & (MAX_SLICES - 1)` — while still in `[0, MAX_SLICES)`
  due to the mask in two's complement — produces an *unexpected* slot,
  corrupting the `slice_row` ring-buffer bookkeeping.

**Impact:** Decoder state corruption and UB on adversarial input. Reset/validate
`h->current_slice` per frame and treat excessive slice counts as a hard error
rather than a soft warning.

---

### 3. The mask only works if `MAX_SLICES` is a power of two

```c
h->slice_row[(sl->slice_num - 1) & (MAX_SLICES - 1)]
```

`x & (MAX_SLICES - 1)` is a valid modulo replacement **only** when `MAX_SLICES`
is a power of two. If `MAX_SLICES` is ever changed to a non-power-of-two value
(the warning message literally invites users to "increase MAX_SLICES and
recompile"), `MAX_SLICES - 1` ceases to be an all-ones mask and the computed
index can both skip valid slots and, depending on the value, **exceed the array
bounds → out-of-bounds read/write** on `slice_row[]`.

**Impact:** Latent OOB vulnerability gated on a build-time constant the comment
encourages users to edit. Use an explicit `% MAX_SLICES`, or add a
`static_assert`/compile-time check that `MAX_SLICES` is a power of two.

---

### 4. Missing input validation on referenced parameter-set fields

```c
sl->qp_thresh = 15 -
                FFMIN(h->ps.pps->chroma_qp_index_offset[0],
                      h->ps.pps->chroma_qp_index_offset[1]) +
                6 * (h->ps.sps->bit_depth_luma - 8);
```

- `h->ps.pps` and `h->ps.sps` are dereferenced with **no NULL check**. If a
  slice references a PPS/SPS that was never activated (a malformed stream can do
  this), these are NULL-pointer dereferences → crash / DoS.
- `bit_depth_luma` and `chroma_qp_index_offset[]` are derived from
  bitstream-controlled parameter sets. If they are not validated upstream,
  `6 * (bit_depth_luma - 8)` and the `qp_thresh` arithmetic can produce
  out-of-expected-range values that later index QP tables. The correctness of
  `qp_thresh` depends entirely on guarantees made elsewhere; this function makes
  none of them locally.

**Impact:** Potential NULL deref / out-of-range derived value. Validate
`h->ps.pps`/`h->ps.sps` are non-NULL before use, or document the invariant that
guarantees it.

---

### 5. `nal` parameter is unused

The `const H2645NAL *nal` argument is never referenced in the body. This is
harmless but worth noting — it usually indicates either dead code, a removed
check, or an intended use that was dropped during refactoring (which can itself
be the source of a missing validation step).

---

## Recommended Fixes (priority order)

1. **Add NULL checks** for `h->ps.pps` / `h->ps.sps` before dereferencing.
2. **Bound / reset `h->current_slice`** and reject streams with excessive slice
   counts as a hard error instead of only logging a warning.
3. **Reorder the slice-overflow condition** so `sl->slice_num >= MAX_SLICES`
   gates the `slice_row[]` reads.
4. **Guarantee `MAX_SLICES` is a power of two** (compile-time assert) or switch
   the index math to `% MAX_SLICES`.
5. Confirm `slice_num` cannot go negative; use an unsigned counter or saturate.

---

## Severity Assessment

| # | Issue | Type | Severity |
|---|-------|------|----------|
| 1 | Short-circuit ordering breaks overflow guard | Logic / diagnostic | Low–Medium |
| 2 | Unbounded `current_slice` increment → signed overflow / negative index | UB / state corruption | Medium |
| 3 | `& (MAX_SLICES-1)` assumes power-of-two | Latent OOB | Medium (High if constant edited) |
| 4 | No NULL/range check on `ps.pps`/`ps.sps` | NULL deref / DoS | Medium–High |
| 5 | Unused `nal` parameter | Code smell | Informational |
