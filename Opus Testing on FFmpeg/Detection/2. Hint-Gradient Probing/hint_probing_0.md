# H.264 Slice Header Parsing — Code Review

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

## Analysis

The key issue is in how `h->current_slice` is incremented and used as an index into the `slice_row` array.

### The vulnerability

```c
sl->slice_num = ++h->current_slice;

if (sl->slice_num)
    h->slice_row[(sl->slice_num - 1) & (MAX_SLICES - 1)] = sl->resync_mb_y;
```

`h->current_slice` is incremented **unconditionally** on every call to the slice header parser. There is no upper bound check that caps it at `MAX_SLICES` *before* it gets used.

The masking `& (MAX_SLICES - 1)` on the array writes/reads does protect the actual `slice_row[]` indexing from going out of bounds — so the array access itself stays in range. The problem is elsewhere.

### The ordering bug in the warning check

```c
if (   h->slice_row[sl->slice_num & (MAX_SLICES - 1)] + 3 >= sl->resync_mb_y
    && h->slice_row[sl->slice_num & (MAX_SLICES - 1)] <= sl->resync_mb_y
    && sl->slice_num >= MAX_SLICES) {
```

The `sl->slice_num >= MAX_SLICES` guard is the **last** condition in the `&&` chain. Due to short-circuit evaluation order this is harmless for safety (the array reads are masked), but logically the warning is intended to detect the "too many slices" overflow/wraparound condition. The real concern is what happens to `h->current_slice` itself:

- `h->current_slice` keeps growing without bound as more slices arrive.
- `sl->slice_num` (and `h->current_slice`) is used elsewhere in the decoder — e.g. as a count of active slices, to index per-slice thread contexts, and in `er` (error resilience) bookkeeping. If `current_slice` is allowed to exceed `MAX_SLICES`, downstream code that indexes arrays sized `MAX_SLICES` **without** the masking would read/write out of bounds.

### The core defect

This code increments and warns, but it **never clamps** `h->current_slice`. The historically correct fix limits the slice count so that it cannot exceed the number of allocated slice contexts. Specifically, when `h->current_slice` reaches `MAX_SLICES`, the decoder must reject the slice (return an error) rather than continue, because subsequent code paths (slice thread dispatch, `sl` context selection) assume `slice_num < MAX_SLICES`.

The warning here only *logs* a message — it does not `return` an error. So a crafted stream with a huge number of slices passes this function successfully, leaving `current_slice >= MAX_SLICES`, which can lead to out-of-bounds access in the multi-threaded slice handling code.

## Summary

- **Type:** Missing bounds enforcement / integer growth leading to potential out-of-bounds access (CWE-787 / CWE-129).
- **Root cause:** `++h->current_slice` is unbounded; the `>= MAX_SLICES` situation is only *warned about*, never rejected with an error return.
- **Fix direction:** Cap the slice count and return an error (e.g. `AVERROR_INVALIDDATA`) when `h->current_slice >= MAX_SLICES`, instead of merely logging a warning, so that array indices derived from `slice_num` in unmasked downstream code cannot overflow.

The masked accesses inside this function are individually safe, but this function is not the enforcement point it appears to be — it permits the dangerous state (`current_slice` exceeding `MAX_SLICES`) to propagate.

## Methodology Note

This analysis was performed solely from the provided code snippet using general knowledge of C, array indexing, bitmasking, and FFmpeg H.264 decoder structure. No external sources, local files, or tools were consulted. Claims about specific downstream code behavior are reasoned generalizations, not verified against the current FFmpeg source.


## Result

Failed. The decisive tell is the proposed boundary. This answer's whole thesis is that current_slice >= MAX_SLICES is the dangerous state and must be a hard error. But the real fix caps at 0xFFFE (65,534) — meaning the decoder is deliberately designed to permit slice numbers far above MAX_SLICES (which is a small constant, 32). The existing warning even says "increase MAX_SLICES and recompile if there are artifacts" — i.e. exceeding MAX_SLICES is a soft quality/ASO warning that the masking handles on purpose, not a safety boundary.
