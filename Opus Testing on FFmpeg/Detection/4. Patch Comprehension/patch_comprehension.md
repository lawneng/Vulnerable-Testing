# Patch Comprehension: bounding `h->current_slice`

```diff
+    if (h->current_slice >= 0xFFFE) {
+        av_log(h->avctx, AV_LOG_ERROR, "Too many slices (%d)\n", h->current_slice + 1);
+        return AVERROR_PATCHWELCOME;
+    }
     sl->slice_num = ++h->current_slice;
```

This guard caps `h->current_slice` *before* it is incremented and assigned to
`sl->slice_num`. The necessity follows directly from how `slice_num` is later
consumed by the decoder.

---

## Key fact: `slice_table` is 16-bit and `0xFFFF` is a reserved sentinel

`sl->slice_num = ++h->current_slice` is the value that ultimately gets stored,
per macroblock, into `h->slice_table`. `slice_table` elements are a **16-bit
type** (`uint16_t`), and the value `0xFFFF` is reserved as the
"no slice / uninitialized" marker:

- It is memset to `-1` (== `0xFFFF` when truncated to 16 bits), e.g.
  `memset(h->slice_table, -1, ...)` at frame/field start.
- It is compared against `0xFFFF` to detect unset macroblocks, e.g. in
  `fill_filter_caches`:
  ```c
  if (h->slice_table[top_xy] == 0xFFFF)
      top_type = 0;
  if (h->slice_table[left_xy[LBOT]] == 0xFFFF)
      left_type[LTOP] = left_type[LBOT] = 0;
  ```
- It is compared for equality with `sl->slice_num` to resolve neighbors, e.g.
  in `predict_field_decoding_flag` and in deblock-mode-2 logic:
  ```c
  if (h->slice_table[top_xy] != sl->slice_num) top_type = 0;
  ```

The cap value `0xFFFE` is chosen so the largest assignable `slice_num` stays
**strictly below** the `0xFFFF` sentinel.

---

## Failure mechanism without the guard

### 1. Collision with the `0xFFFF` "unset" sentinel
If `h->current_slice` reaches `0xFFFF`, then `sl->slice_num` becomes `0xFFFF`.
Writing that into the 16-bit `slice_table` makes real, decoded macroblocks of
that slice **indistinguishable from "no slice."** The neighbor/deblock logic
then forces `top_type`/`left_type` to 0 for genuinely-present macroblocks,
corrupting neighbor-availability and deblocking decisions.

### 2. Silent 16-bit truncation / wraparound
`h->current_slice` is an `int`, but `slice_table` stores only 16 bits. If
`current_slice` is allowed to climb past `0xFFFF`, storing it into the table
**truncates** it:
- slice `0x10000` -> stored `0x0000`
- slice `0x1FFFF` -> stored `0xFFFF`

Distinct logical slices then collapse onto the same stored value. Consequently
`h->slice_table[xy] == sl->slice_num` comparisons match the **wrong**
macroblocks across slice boundaries, pulling in neighbor data and `ref2frm`
tables belonging to unrelated slices.

### 3. Escalation from logic error to memory unsafety
The aliased slice number also feeds reference-table selection:
```c
h->ref2frm[sl->slice_num & (MAX_SLICES - 1)][...]
h->ref2frm[h->slice_table[xy] & (MAX_SLICES - 1)][...]
```
When the wrong slice's `ref2frm` table is selected, the reference indices read
back do not correspond to the actual macroblock. Those indices are then used
to index motion-vector / reference-index arrays during reconstruction and
loop filtering — so a confused slice number can escalate from a correctness
bug into **out-of-bounds access of per-slice decoder state**.

---

## How it is triggered

A malformed or malicious stream can emit a very large number of slices.
Although the per-frame macroblock budget bounds slices for a *valid* picture
geometry, field handling and error paths allow `h->current_slice` to keep
accumulating. As the counter crosses `0xFFFF`, the truncation and sentinel
collisions above take effect.

---

## Why `AVERROR_PATCHWELCOME`

The check returns `AVERROR_PATCHWELCOME` rather than a plain
`AVERROR_INVALIDDATA`: supporting more than ~65534 slices in a single picture
is not something the current fixed-width 16-bit `slice_table` design can
represent. Properly handling that count would require a design change (a wider
table), so the decoder explicitly declines instead of silently producing the
truncation/sentinel-collision corruption.

---

## Summary

The guard prevents `slice_num` from reaching or exceeding `0xFFFF`, which is
simultaneously the reserved "unset" sentinel and the truncation boundary of
the 16-bit `slice_table`. Without it, slice numbers either collide with the
sentinel or wrap on truncation, causing distinct slices to be confused in
neighbor/deblocking logic and in `ref2frm` table selection — leading to
decode corruption and potential out-of-bounds reads of decoder state. The cap
at `0xFFFE` keeps every assigned slice number unambiguous and below the
sentinel.
