# Analysis: `h264_decode_slice_header`

## Summary

The function contains a **memory-safety bug (out-of-bounds array read/write)** in the way it indexes the `h->slice_row[]` array using `sl->slice_num`, and several related correctness problems.

---

## Bug 1: Out-of-bounds access on `h->slice_row[]` (primary bug)

```c
sl->slice_num = ++h->current_slice;

if (sl->slice_num)
    h->slice_row[(sl->slice_num - 1) & (MAX_SLICES - 1)] = sl->resync_mb_y;

if (   h->slice_row[sl->slice_num & (MAX_SLICES - 1)] + 3 >= sl->resync_mb_y
    && h->slice_row[sl->slice_num & (MAX_SLICES - 1)] <= sl->resync_mb_y
    && sl->slice_num >= MAX_SLICES) {
    ...
}
```

### Problem
The masking `& (MAX_SLICES - 1)` is only safe as a way of wrapping the index
into the array **if `MAX_SLICES` is a power of two**. The expression
`x & (MAX_SLICES - 1)` is the canonical "modulo by power-of-two" idiom and
keeps the index within `[0, MAX_SLICES - 1]` **only under that assumption**.

- If `MAX_SLICES` is *not* a power of two (e.g. a value like 32 happens to be
  one, but the code does not enforce this anywhere visible in this scope), then
  `(MAX_SLICES - 1)` is not an all-ones bitmask, and the masked value can be a
  larger index than `MAX_SLICES - 1`, producing an **out-of-bounds read and
  write** into `h->slice_row[]`.
- This indexing is done with attacker-influenced data: `h->current_slice` is
  incremented once per slice and the number of slices in a frame is controlled
  by the bitstream. A malicious stream can drive `current_slice` to arbitrary
  values.

The correctness of this whole block is therefore *implicitly* dependent on an
invariant (`MAX_SLICES` is a power of two) that is not validated here.

---

## Bug 2: Logic-ordering / unreachable diagnostic (correctness bug)

The `av_log` warning is intended to detect "too many slices". However, the
condition is:

```c
if (   h->slice_row[idx] + 3 >= sl->resync_mb_y
    && h->slice_row[idx] <= sl->resync_mb_y
    && sl->slice_num >= MAX_SLICES)
```

### Problems
1. **The slice count is only checked *after* the array has already been read
   and written.** The store
   `h->slice_row[(sl->slice_num - 1) & (MAX_SLICES - 1)] = sl->resync_mb_y;`
   and the loads `h->slice_row[sl->slice_num & (MAX_SLICES - 1)]` happen
   *before* the `sl->slice_num >= MAX_SLICES` guard. If the intent was to
   guard array access by slice count, the check is in the wrong place — the
   guard does not protect the accesses, it only gates the log message.

2. **`sl->slice_num` is signed (`int`) and can overflow.** `++h->current_slice`
   has no upper bound in this function. On a long stream with many slices,
   `current_slice` can overflow `INT_MAX`, which is **undefined behavior** in C
   for signed integers, and afterwards `sl->slice_num` may become negative.

---

## Bug 3: Negative index when `sl->slice_num` becomes negative

If `sl->slice_num` overflows to a negative value (see Bug 2), then:

```c
h->slice_row[(sl->slice_num - 1) & (MAX_SLICES - 1)]
```

The masking with `& (MAX_SLICES - 1)` would normally still clamp the *result*
into range for power-of-two `MAX_SLICES` (bitwise AND on a negative two's
complement value yields a non-negative result within the mask). However the
`if (sl->slice_num)` guard around the **write** is checking only for zero, not
for negativity — so the semantics of the index after overflow are not what the
author intended even if no OOB occurs, leading to **corrupted `slice_row`
bookkeeping** and incorrect artifact detection.

---

## Bug 4: Suspicious / contradictory comparison logic

```c
   h->slice_row[idx] + 3 >= sl->resync_mb_y
&& h->slice_row[idx]     <= sl->resync_mb_y
```

This asks for `slice_row[idx]` to be within `[resync_mb_y - 3, resync_mb_y]`.
Combined with `slice_num >= MAX_SLICES`, the index `idx = slice_num &
(MAX_SLICES - 1)` *aliases* a previously-used slot (because of wraparound).
The comparison therefore reads a **stale value from a different slice's slot**
to decide whether to warn, which is a heuristic at best. It is not a hard
memory-safety bug by itself, but the logic conflates the wrapped slot of a
*different* slice with the current one, which is a correctness smell.

---

## Recommendations

1. **Validate the index before any access.** Clamp/guard `sl->slice_num`
   explicitly, e.g. reject or saturate when `current_slice >= MAX_SLICES`
   *before* touching `slice_row[]`, rather than after.
2. **Use an explicit bounds check** instead of relying on the
   `& (MAX_SLICES - 1)` idiom, or `static_assert`/`AV_BUILD_ASSERT` that
   `MAX_SLICES` is a power of two.
3. **Prevent signed overflow** of `h->current_slice` (saturate it, or use an
   unsigned type with a defined wrap, and guard reads accordingly).
4. **Reorder the slice-count guard** so the `slice_num >= MAX_SLICES` check
   gates the array accesses, not just the log message.

---

## Severity

- Bug 1 / Bug 3: **High** — potential out-of-bounds read/write driven by
  bitstream-controlled slice count (memory-safety / possible crash or
  corruption).
- Bug 2: **Medium** — undefined behavior via signed overflow.
- Bug 4: **Low** — correctness/heuristic-quality issue, no direct memory unsafety.


## Result

It never identifies the actual bug — a real slice's number reaching 0xFFFF and colliding with the 0xFFFF "no slice" sentinel in the uint16_t slice_table. Its self-declared primary bug (OOB because MAX_SLICES might not be a power of two) is essentially a non-bug: MAX_SLICES is a fixed power-of-two compile-time constant, so the mask is always a valid all-ones mask and the slice_row[] access is in-bounds — the model even concedes "32 happens to be one."
