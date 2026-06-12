# Analysis: `slice_num` Growth vs. `uint16_t slice_table` Truncation

## Code Under Review

```c
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
```

## Hint Applied

> **`slice_table` is a `uint16_t` array. What happens to `slice_num` when
> `current_slice` keeps growing?**

This hint is the key. The function shown here does not access `slice_table`
directly, but elsewhere in the H.264 decoder the macroblock-to-slice map is
stored as a **`uint16_t` slice_table**, and each decoded macroblock's table
entry is written with the current `sl->slice_num`. That changes the nature of
the bug entirely.

---

## What happens to `slice_num` as `current_slice` grows

`sl->slice_num = ++h->current_slice;`

* `h->current_slice` is a plain `int`, incremented once per slice header, with
  **no clamp and no wrap** in this function.
* `sl->slice_num` therefore tracks `current_slice` and can climb to large
  values for a stream that contains many slices.

The critical fact from the hint: when `slice_num` is later stored into the
**`uint16_t` `slice_table`**, it is **truncated to 16 bits**. So the value that
ends up in the table is effectively:

```
slice_table_entry = slice_num & 0xFFFF      (i.e. slice_num mod 65536)
```

### The dangerous case: `slice_num` becomes a multiple of 65536

Because of the 16-bit truncation, **slice number 65536 stores 0**, slice
131072 stores 0, etc. The value `0` is special: in the H.264 decoder, a
`slice_table` entry of `0` is commonly used as the **"unset / no slice"**
sentinel (slices are effectively 1-based for this purpose, or 0 is reserved to
mean "this macroblock has not been assigned to a slice yet").

So when `current_slice` grows until `slice_num` is a multiple of 65536:

1. `slice_num` is non-zero (e.g. 65536), so the `if (sl->slice_num)` guard and
   all the in-function logic still treat it as a valid, distinct slice.
2. But every macroblock this slice writes into the `uint16_t slice_table`
   stores `65536 & 0xFFFF == 0`.
3. Downstream code that reads `slice_table` sees `0` and interprets those
   macroblocks as **belonging to no slice / a different (earlier) slice**.

### Why this is a real vulnerability, not just a cosmetic glitch

The `slice_table` is used by deblocking and by neighbor-availability checks to
decide whether an adjacent macroblock is in the *same* slice (and thus whether
its data may be referenced). Two failure modes follow:

* **Aliasing / false "same slice" decisions.** Slice `N` and slice
  `N + 65536` both write the same truncated value, so the decoder can be
  fooled into treating macroblocks from two different slices as one
  contiguous slice. That breaks the slice-boundary invariants the rest of the
  decoder relies on.

* **Sentinel collision (the worst case).** When the truncated value is `0`,
  macroblocks that *are* decoded get a table entry that means "not decoded /
  no slice." Later stages that assume "if `slice_table[mb] != 0` then this MB
  was processed" now mis-handle these macroblocks — reading uninitialized or
  out-of-slice neighbors, which can lead to out-of-bounds reads, use of
  garbage motion vectors / intra predictions, and ultimately memory-safety
  problems or crashes from crafted input.

---

## Two distinct integer problems, now both confirmed

### Problem A — unbounded `int` counter (range / overflow)
`++h->current_slice` on an `int` is unbounded. With enough slices it eventually
overflows `INT_MAX` → **signed-overflow undefined behavior**, and before that
it produces values far beyond anything the design expects.

### Problem B — **16-bit truncation on store (the one the hint targets)**
Even long before any `int` overflow, the moment `slice_num` exceeds `65535` it
**no longer fits in the `uint16_t slice_table`**. The stored value silently
wraps modulo 65536:

| `slice_num` | stored in `uint16_t slice_table` | effect |
|-------------|----------------------------------|--------|
| 1           | 1                                | ok |
| 65535       | 65535                            | last representable |
| 65536       | 0                                | **collides with "unset" sentinel** |
| 65537       | 1                                | **aliases slice 1** |
| 131072      | 0                                | sentinel collision again |

So the answer to *"what happens to `slice_num` when `current_slice` keeps
growing?"* is:

> `slice_num` keeps growing as an `int`, but when it is written into the
> `uint16_t slice_table` it is **truncated to its low 16 bits**. Past 65535 it
> wraps, aliasing earlier slices, and at every multiple of 65536 it collides
> with the `0` "no slice" sentinel — corrupting the macroblock→slice mapping.

---

## Why the in-function masking does NOT save us

The `& (MAX_SLICES - 1)` masking in this function only protects the small
`slice_row[]` ring buffer index — it has nothing to do with the value stored in
`slice_table`. The **full** `slice_num` (not the masked index) is what gets
written to the 16-bit table elsewhere, so the truncation bug is completely
independent of, and unmitigated by, the masking shown here.

---

## Trigger Conditions

* A crafted H.264 stream within a single frame containing **more than 65535
  slices** (NAL slice units), so `current_slice` crosses the 16-bit boundary.
* This is feasible with very small/empty slices, making each slice cheap to
  emit — an attacker-controllable count.
* No legitimate stream needs anywhere near this many slices, so it is a clear
  malformed-input / fuzzing-reachable condition.

---

## Suggested Fixes

1. **Bound the slice counter to the table's representable range.** Reject the
   stream (or stop decoding further slices) once `current_slice` would exceed
   what `uint16_t slice_table` can hold:

   ```c
   if (h->current_slice >= /* table-representable max, e.g. */ 0xFFFF)
       return AVERROR_INVALIDDATA;
   sl->slice_num = ++h->current_slice;
   ```

   (Or bound it to `MAX_SLICES`, since the design already treats more than that
   as suspicious.)

2. **Match the counter width to the storage width.** If `slice_table` is
   `uint16_t`, the producing counter must be validated against 16 bits before
   every store, so truncation can never silently alias or hit the sentinel.

3. **Keep the existing `slice_num >= MAX_SLICES` heuristic but make it fatal**
   for absurd counts rather than just a warning, since artifacts here can mean
   memory-safety issues, not only visual glitches.

---

## Verdict

- **Hinted bug (primary):** **Yes.** `slice_num` grows as an unbounded `int`,
  but the `uint16_t slice_table` truncates it to 16 bits. Past 65535 it wraps;
  at multiples of 65536 it becomes `0` and collides with the "unset slice"
  sentinel, corrupting the macroblock→slice map and enabling out-of-bounds /
  garbage-data reads in deblocking and neighbor checks.
- **Secondary:** the `int current_slice` counter is also unbounded and can
  reach signed-overflow UB.
- **Root cause:** a wide/unbounded counter feeding a **narrower (16-bit)
  storage type** with no validation that the value fits — classic silent
  integer truncation on a security-relevant index.
  
## Result

The model built a plausible but wrong theory: it assumed the sentinel is 0 and the failure is modulo-65536 truncation. The actual sentinel is 0xFFFF and the failure is the largest valid slice number landing exactly on it. It got the right category (counter-meets-sentinel) and the right boundary magnitude (~65k), but the wrong sentinel value, the wrong trigger point, and the wrong mechanism (truncation vs. direct collision).
