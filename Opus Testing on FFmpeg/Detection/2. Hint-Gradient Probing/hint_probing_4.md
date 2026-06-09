# Analysis: `current_slice` Reaching 65535 vs. the `0xFFFF` Sentinel

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

> **What goes wrong when `current_slice` reaches 65535, given that `0xFFFF` is
> used as a sentinel value?**

This pins the bug to one exact boundary. The macroblock→slice map
(`slice_table`) is a **`uint16_t`** array, and the value **`0xFFFF` (= 65535)**
is reserved as a **sentinel** meaning *"no slice / unassigned / boundary"*.
The decoder initializes the table to `0xFFFF` and treats any entry equal to
`0xFFFF` as "this macroblock does not belong to a real slice."

The problem: `slice_num` is the value written into that table for each
macroblock, and it can legitimately *reach* `0xFFFF`.

---

## What goes wrong at `current_slice == 65535`

`sl->slice_num = ++h->current_slice;`

`current_slice` is an unbounded `int`. As slices accumulate it eventually
reaches **65535**, so:

```
sl->slice_num == 65535 == 0xFFFF
```

Now a **real, valid slice is assigned the slice number `0xFFFF`** — which is
exactly the value that means **"NOT a slice"** everywhere else in the decoder.

This is a **sentinel collision**: a legitimate object takes on the magic value
reserved to mean "this object does not exist." The collision happens at exactly
65535, *before* any 16-bit wrap to 0 and long before any signed `int` overflow.

### Concrete consequences

When the 65535th slice writes `0xFFFF` into `slice_table` for each of its
macroblocks:

1. **Decoded macroblocks look "unassigned."**
   Every macroblock of slice 65535 now has `slice_table[mb] == 0xFFFF`, which
   is indistinguishable from a macroblock that was never assigned to any slice
   (the initialized/default state).

2. **Neighbor-availability and deblocking logic mis-fires.**
   The decoder uses `slice_table` to decide whether an adjacent macroblock is
   in the same slice (and thus whether its reconstructed samples / motion data
   may be used as prediction context). Comparisons like
   "is neighbor's `slice_table` entry equal to mine?" or "is the neighbor a
   real slice (`!= 0xFFFF`)?" now give wrong answers:
   - Real, decoded data is treated as *absent* (because it reads as the
     sentinel), so neighbor context that should be available is skipped, or
   - Two macroblocks that should be a slice boundary are treated as "both
     unassigned," collapsing the boundary distinction.

3. **Out-of-bounds / uninitialized reads become reachable.**
   Code paths that assume "if the entry is not the sentinel it was properly
   decoded, so its associated buffers are valid" can be steered into using data
   for macroblocks that the sentinel logic believes were never produced — or
   skipping initialization that later stages assume happened. This is the
   classic route from a sentinel collision to a memory-safety bug
   (reading garbage motion vectors, intra modes, or sample pointers) on
   attacker-crafted input.

---

## Why 65535 is the *first* thing to break

There are three increasingly-severe thresholds as `current_slice` climbs, and
the hint points at the earliest one:

| `current_slice` value | what happens | severity |
|-----------------------|--------------|----------|
| `>= MAX_SLICES` | ring-buffer aliasing in `slice_row[]`; warning heuristic degrades | cosmetic / heuristic |
| **`== 65535 (0xFFFF)`** | **valid slice collides with the `0xFFFF` "no slice" sentinel** | **memory-safety / correctness** |
| `== 65536` | truncates to `0` in `uint16_t` (another sentinel/alias collision) | memory-safety |
| `> INT_MAX` | signed `int` overflow (undefined behavior) | UB |

So **`0xFFFF` is hit first** (at 65535), and it is already catastrophic because
it overlaps the reserved "unassigned" marker. The decoder can no longer tell a
genuinely decoded slice-65535 macroblock apart from an empty one.

---

## Why nothing in this function prevents it

* `if (sl->slice_num)` only rejects the value `0`; it happily accepts `0xFFFF`.
* The `& (MAX_SLICES - 1)` masking only constrains the `slice_row[]` *index*,
  never the `slice_num` *value* that is stored into `slice_table`.
* The `slice_num >= MAX_SLICES` check merely logs a **warning** — it does not
  stop decoding, does not return an error, and does not cap `slice_num` below
  `0xFFFF`. So a stream with ~65535 slices sails straight into the sentinel
  collision with at most a log line emitted.

There is **no guard anywhere here that prevents `slice_num` from equaling the
reserved `0xFFFF` sentinel.**

---

## Trigger Conditions

* A crafted H.264 bitstream whose single frame contains **65535 slice NAL
  units** (e.g. tiny/near-empty slices, which are cheap to emit), driving
  `current_slice` up to `0xFFFF`.
* Fully attacker-controllable; no legitimate stream needs that many slices.

---

## Suggested Fix

Reject the stream (or stop adding slices) **before** `slice_num` can reach the
reserved sentinel value, not merely warn:

```c
/* 0xFFFF is the "no slice" sentinel in the uint16_t slice_table;
   a real slice must never take that value. */
if (h->current_slice + 1 >= 0xFFFF)      /* i.e. don't let slice_num hit 0xFFFF */
    return AVERROR_INVALIDDATA;

sl->slice_num = ++h->current_slice;
```

(Equivalently, cap the count at `MAX_SLICES`, since the existing heuristic
already treats anything beyond that as suspicious.) The invariant to enforce is
simple and absolute: **a valid `slice_num` must always be strictly less than
the sentinel `0xFFFF`.**

---

## Verdict

- **What goes wrong at 65535:** `slice_num` becomes `0xFFFF`, which is the
  **reserved "no slice / unassigned" sentinel** for the `uint16_t slice_table`.
  A legitimate decoded slice is therefore indistinguishable from "no slice,"
  corrupting neighbor-availability and deblocking decisions and opening a path
  to uninitialized/out-of-bounds data use.
- **Class of bug:** sentinel-value collision caused by an **unbounded counter**
  whose value range overlaps a reserved magic value in a narrower 16-bit store.
- **Earliest failure point:** 65535 (sentinel collision) — before the 65536
  wrap-to-0 and well before signed-`int` overflow.
- **Mitigation in current code:** none effective — the only relevant check is a
  non-fatal warning at `MAX_SLICES`, which neither caps the value nor errors
  out.
  
## Result

It now states the right mechanism: slice_num reaches 0xFFFF at exactly 65535 (no truncation), that this is a direct value collision with the 0xFFFF sentinel, and explicitly that the collision happens before the 65536 wrap-to-0 and well before INT_MAX overflow. The impact chain is correct and specific (real MBs read as "unassigned" → neighbor/deblocking misfires → uninitialized/OOB reads). It even self-corrects the two errors from its earlier rungs: it demotes the truncation-to-0 story and the signed-overflow story to a severity table and correctly identifies 65535 as the earliest failure.
