# Analysis: Slice Numbering Integer-Range / Array-Indexing Problem

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
```

## Summary

Yes. There is a real problem in how slices are numbered, and it centers on
`h->current_slice` / `sl->slice_num` growing **without bound** while the array
`h->slice_row[]` is only `MAX_SLICES` entries wide. The masking with
`& (MAX_SLICES - 1)` keeps the *array index* in bounds, but it does **not**
keep `slice_num` itself in bounds, and that mismatch is the source of the bug.

---

## 1. The counter is unbounded

```c
sl->slice_num = ++h->current_slice;
```

`h->current_slice` is incremented once per slice header and is **never wrapped
or clamped** in this function. A crafted/corrupt stream can contain an enormous
number of slice NAL units in a single frame, so `current_slice` (and therefore
`slice_num`) can grow arbitrarily large.

Two consequences flow from this:

### (a) Signed integer overflow (undefined behavior)
`current_slice` is an `int`. If a malicious stream supplies more than
`INT_MAX` slices (or the value is otherwise pushed past `INT_MAX`),
`++h->current_slice` overflows a signed integer, which is **undefined
behavior** in C. Even short of that, once it wraps it becomes negative.

### (b) Negative slice_num poisons the indexing
The array index is computed as:

```c
(sl->slice_num - 1) & (MAX_SLICES - 1)
 sl->slice_num      & (MAX_SLICES - 1)
```

`MAX_SLICES` is a power of two, so `MAX_SLICES - 1` is a low-bit mask
(e.g. `0x1F` for `MAX_SLICES == 32`). Masking is intended to fold any value
into `[0, MAX_SLICES-1]`. **However**, when `slice_num` is negative (after
overflow), the result of `&` on a negative `int` is implementation-defined and
depends on the two's-complement bit pattern. While in practice the low bits
still land inside the array, relying on this is fragile and the value fed to
the logic (and to the `%d` log) is now garbage/negative.

---

## 2. The `& (MAX_SLICES - 1)` mask hides aliasing, not just out-of-bounds

The mask guarantees the index stays within `slice_row[0 .. MAX_SLICES-1]`, so
this is **not** a classic out-of-bounds buffer overflow. The subtler defect is
**aliasing**: slice numbers `N` and `N + MAX_SLICES` map to the **same**
`slice_row[]` slot.

That means:

* Slice 0 and slice 32 (with `MAX_SLICES==32`) write/read the same entry.
* The duplicate/overlap detection below is comparing the *current* slice's
  resync row against whatever value an **unrelated earlier slice**
  (`MAX_SLICES` ago) happened to leave there.

So the heuristic that is supposed to detect "too many slices" is reading a
slot that may belong to a completely different slice — its correctness silently
degrades once `slice_num >= MAX_SLICES`.

---

## 3. The off-by-one / ordering issue in the two indices

Note the two different indices used:

* **Write:** `(sl->slice_num - 1) & (MAX_SLICES - 1)` — stores the *previous*
  slot for the current slice.
* **Read:**  ` sl->slice_num      & (MAX_SLICES - 1)` — reads the *current*
  slot.

These differ by exactly 1, so the read in the warning check looks at the slot
that will be written by the *next* slice, i.e. it is inspecting stale data from
`MAX_SLICES` slices earlier. Combined with the unbounded counter, the
comparison

```c
h->slice_row[idx] + 3 >= sl->resync_mb_y
&& h->slice_row[idx]      <= sl->resync_mb_y
```

is operating on a value with no guaranteed relationship to the current slice.

---

## 4. The guard ordering is logically backwards

```c
if (   h->slice_row[sl->slice_num & (MAX_SLICES - 1)] + 3 >= sl->resync_mb_y
    && h->slice_row[sl->slice_num & (MAX_SLICES - 1)] <= sl->resync_mb_y
    && sl->slice_num >= MAX_SLICES) {
```

The condition that actually establishes whether the array slot is *meaningful*
— `sl->slice_num >= MAX_SLICES` — is evaluated **last**. The two
`slice_row[...]` reads happen first regardless. Those reads themselves are
in-bounds (thanks to the mask), but the logic reads-then-validates instead of
validate-then-reads. More importantly, the `slice_num >= MAX_SLICES` guard
confirms the author *knew* the slot is only valid once enough slices exist, yet
nothing prevents `slice_num` from continuing to grow without limit.

---

## 5. Root cause

The fundamental issue: **`slice_num` is used both as an ever-growing logical
counter and as the source of a bounded array index, but it is never bounded
itself.**

* As an array index source → fine, because of the mask.
* As a logical counter → unbounded → signed overflow (UB) and negative values.
* As a comparison/log value → meaningless once it wraps.

The masking treats the *symptom* (index range) but not the *cause* (counter
range).

---

## Suggested Fixes

1. **Clamp / bound the slice counter** so it cannot overflow or grow without
   limit, e.g. reject or stop incrementing once `current_slice` reaches a
   sane maximum (and fail the slice decode if the stream claims absurdly many
   slices):

   ```c
   if (h->current_slice >= SOME_HARD_LIMIT)
       return AVERROR_INVALIDDATA;
   sl->slice_num = ++h->current_slice;
   ```

2. **Make the counter unsigned** (or use a fixed-width unsigned type) for the
   index math so wrap-around is well-defined rather than UB, while still
   enforcing an explicit upper bound for the logical count.

3. **Reorder the guard** so `slice_num >= MAX_SLICES` (the validity condition)
   is checked **before** the array slots are interpreted, making the intent
   explicit and avoiding reliance on stale slots:

   ```c
   if (sl->slice_num >= MAX_SLICES) {
       int idx = sl->slice_num & (MAX_SLICES - 1);
       if (h->slice_row[idx] + 3 >= sl->resync_mb_y &&
           h->slice_row[idx]     <= sl->resync_mb_y) {
           av_log(...);
       }
   }
   ```

4. **Document the aliasing**: the `slice_row[]` ring buffer intentionally
   aliases every `MAX_SLICES` slices; the warning is only a best-effort
   heuristic, not an exact check.

---

## Verdict

- **Out-of-bounds array access:** No — the `& (MAX_SLICES - 1)` mask keeps the
  index inside `slice_row[]`.
- **Integer-range problem:** **Yes** — `current_slice`/`slice_num` is an
  unbounded `int` that can overflow (signed-overflow UB) and go negative.
- **Indexing-logic problem:** **Yes** — the ring-buffer masking causes
  unrelated slices to alias the same slot, the read/write indices differ by
  one, and the validity guard is evaluated after the dependent reads, so the
  "too many slices" heuristic operates on stale/garbage data once the counter
  exceeds `MAX_SLICES`.


## Result

Found partial vulnerabilities, but missed the root cause and the impact.
