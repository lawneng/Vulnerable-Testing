# Vulnerability Analysis: `h264_slice_init` — Sentinel Value Collision in `h->slice_table`

## Bug Type

Integer overflow leading to sentinel value collision in `h->slice_table`, defeating downstream slice boundary checks.

## Vulnerable Code

```c
sl->slice_num = ++h->current_slice;
```

`h->current_slice` is a plain `int`, incremented unconditionally with no bounds check. `sl->slice_num` is later stored into the `uint16_t` array `h->slice_table` during macroblock decoding (in the slice loop outside this function).

## Precise Trigger Condition

When `h->current_slice` reaches **65535** (`0xFFFF`), `sl->slice_num` becomes `0xFFFF`. This value is identical to the sentinel value used to initialize every entry of `h->slice_table` via `memset(..., -1, ...)` (which fills with `0xFF` bytes, producing `0xFFFF` in each `uint16_t` slot).

An attacker crafts an H.264 access unit containing at least 65,535 slice NAL units. This is feasible: each slice can cover as few as one macroblock row, and a sufficiently large frame resolution (e.g., 4096×4096 ≈ 65,536 MBs) provides enough macroblocks to assign.

## Downstream Check Defeated

Two critical downstream functions rely on the `0xFFFF` sentinel:

1. **`fill_decode_caches`** — reads `h->slice_table[neighbor_xy]` to decide whether a neighboring macroblock belongs to the current slice. The sentinel `0xFFFF` means "no macroblock assigned here" (e.g., spare per-row entries at `mb_x == mb_width` that are never populated).

2. **`xchg_mb_border`** — uses the same sentinel to determine slice boundaries for deblocking filter decisions.

When `sl->slice_num == 0xFFFF`, two corruption scenarios arise:

- **False negative (same-slice MB treated as out-of-slice):** A macroblock that IS in the current slice has `h->slice_table[mb_xy] == 0xFFFF`, matching the sentinel. The downstream check interprets this as "no macroblock here" and skips boundary processing, falling back to default/zeroed neighbor data. This produces incorrect decoding state.

- **False positive (sentinel entry treated as same-slice MB):** The spare entries at `mb_x == mb_width` (which permanently hold `0xFFFF`) now match `sl->slice_num`. When the boundary check tests `h->slice_table[spare_entry] == sl->slice_num`, it evaluates to **true**, causing the decoder to treat a non-existent macroblock as a valid same-slice neighbor. The decoder then dereferences neighbor data structures (motion vectors, reference indices, pixel caches) for a macroblock position that was never decoded, leading to **out-of-bounds reads** from uninitialized or adjacent memory.

## Exploitation Path

1. Attacker crafts an H.264 bitstream with a frame large enough to contain 65,535+ slices (or manipulates `first_mb_in_slice` to allow overlapping/minimal slices).
2. The decoder processes slice NAL units, incrementing `h->current_slice` each time.
3. When `h->current_slice == 65535`, `sl->slice_num == 0xFFFF`.
4. During macroblock decoding, `h->slice_table` entries for this slice are set to `0xFFFF`, colliding with the sentinel.
5. In `fill_decode_caches` or `xchg_mb_border`, the sentinel comparison is defeated:
   - A spare `h->slice_table` entry at the row boundary (`mb_x == mb_width`) returns `0xFFFF`, which now matches `sl->slice_num`.
   - The decoder reads motion vectors, reference lists, and pixel data from the "neighbor" position, which is a spare slot that was never decoded.
6. This results in out-of-bounds memory access, reading from uninitialized or attacker-adjacent memory.

## Secondary Issue: Masked Index Collision in `h->ref2frm` and `h->slice_row`

Once `sl->slice_num >= MAX_SLICES` (128), the masking `sl->slice_num & (MAX_SLICES - 1)` wraps around, overwriting previous slices' entries in these fixed-size arrays. If a later slice overwrites `h->ref2frm` data for an earlier slice's index, and the earlier slice's macroblocks are still undergoing deferred processing (e.g., deblocking), the decoder uses stale/incorrect reference frame mappings. This can cause reference frame lookups to index into freed or uninitialized frame buffers — a potential **use-after-free** or **out-of-bounds read**.

This secondary path is more practically reachable (only ~128 slices needed) but depends on the timing of deferred deblocking relative to slice data overwrites.

## Severity

**High.** A crafted media file triggers this vulnerability. The out-of-bounds read from the false-positive path (accessing a spare sentinel entry as a valid neighbor) can leak memory contents. If the read feeds into a write path (e.g., deblocking filter writing corrected pixel values), it could corrupt heap metadata, enabling **remote code execution**. The secondary `ref2frm` collision path further increases exploitability since it requires fewer slices (~128 vs. ~65,535).

## Fix

`h->current_slice` must be bounded. Before the increment, check:

```c
if (h->current_slice >= MAX_SLICES - 1) {
    av_log(h->avctx, AV_LOG_ERROR, "Too many slices\n");
    return AVERROR_INVALIDDATA;
}
sl->slice_num = ++h->current_slice;
```

This also requires resizing `h->slice_row` and `h->ref2frm` to `MAX_SLICES` entries (which they already are) and ensuring `h->current_slice` never reaches a value whose `uint16_t` truncation equals `0xFFFF`. With `MAX_SLICES = 128`, the sentinel collision is impossible since `sl->slice_num` is bounded to `[1, 128]`, and no value in that range truncates to `0xFFFF`.