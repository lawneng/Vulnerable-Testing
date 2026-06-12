# Code Review: Video Decoder Frame/Segment Handling

## Primary Vulnerability: Integer Truncation Causing Segment ID Collision with Sentinel Value

### Classification

- **Type:** Integer truncation / type-width mismatch (CWE-681: Incorrect Conversion between Numeric Types)
- **Severity:** High
- **Location:** `segment_begin()`, specifically the assignment `seg->id = ++d->segment_counter;`

### Root Cause

The `segment_counter` field is declared as `unsigned` (32-bit on all common platforms), but it is assigned into `seg->id`, which is of type `seg_id_t` (`uint16_t`). The counter is incremented once per segment parsed from an **untrusted** bitstream, with no upper-bound check. The code's own comment acknowledges this: *"The number of segments comes from the input; it is not bounded here."*

This creates two distinct problems when an attacker supplies a crafted stream with a large number of segments:

#### Problem 1: Sentinel Collision at Counter Value 65535

When `segment_counter` reaches `0xFFFF` (65535), the truncated `seg->id` becomes `0xFFFF`, which is exactly `SEG_NONE` -- the sentinel value meaning "block not yet assigned to any segment."

```c
#define SEG_NONE  0xFFFF

seg->id = ++d->segment_counter;
// When segment_counter == 0xFFFF:
//   seg->id = (uint16_t)0xFFFF == SEG_NONE
```

Any blocks assigned to this segment via:

```c
d->block_segment[mb] = seg->id;  // writes 0xFFFF
```

are subsequently misidentified by `same_segment()` as **unassigned**, because:

```c
if (a == SEG_NONE || b == SEG_NONE)
    return 0;   // treats legitimately-assigned blocks as boundaries
```

This corrupts the loop-filter's boundary decisions. Blocks that belong to a real segment and should be filtered together are instead treated as segment boundaries, causing the loop filter to skip filtering where it should apply it (or vice versa, depending on calling context).

#### Problem 2: Full ID-Space Wraparound Causing Cross-Segment Confusion

Once `segment_counter` exceeds `0xFFFF`, the truncated ID wraps around to 0, then 1, 2, etc.:

| `segment_counter` | `(uint16_t)` result | Collides with segment # |
|---|---|---|
| 65536 | 0 | (invalid / zero-ID edge case) |
| 65537 | 1 | Segment 1 |
| 65538 | 2 | Segment 2 |
| ... | ... | ... |

This means blocks from entirely different segments are stamped with the same ID. `same_segment()` then returns `1` (same segment) for blocks that are actually in different segments, causing the loop filter to **not** apply boundary filtering where it should. Depending on what the loop filter does, this could corrupt decoded frame data.

### Exploitability

An attacker controls the bitstream and therefore controls:
- The number of segments (drives `segment_counter` to any value).
- `first_block` and `block_span` per segment (controls which blocks get which ID).

By crafting a stream with exactly 65535 segments (or 65535 + N to target a specific earlier ID), an attacker can:
1. Force specific blocks to appear unassigned (sentinel collision).
2. Force blocks from different segments to share an ID (wraparound collision).

Both cause incorrect loop-filter decisions, which at minimum corrupt the decoded image and could potentially be leveraged for further exploitation depending on how downstream code uses the filter results (e.g., if filter strength or buffer offsets are segment-dependent).

### The Fix

The counter must either be bounded or the ID type must be widened. The most direct fix:

```c
int segment_begin(DecoderState *d, Segment *seg)
{
    if (d->segment_counter >= SEG_NONE - 1) {
        // Reject: would collide with sentinel or wrap
        return -1;  // error
    }
    seg->id = ++d->segment_counter;
    // ...
}
```

Alternatively, widen `seg_id_t` to `uint32_t` and change `SEG_NONE` to `0xFFFFFFFF`, eliminating the truncation entirely.

---

## Secondary Issue: Missing Bounds Check in `same_segment()`

### Classification

- **Type:** Out-of-bounds read (CWE-125)
- **Severity:** Medium
- **Location:** `same_segment()`, the array accesses `d->block_segment[block_a]` and `d->block_segment[block_b]`

### Description

The function accepts `int block_a` and `int block_b` as indices into `d->block_segment[]` (size `BLOCKS_MAX` = 65536) but performs **no bounds validation**. If the caller passes a negative index or one >= `BLOCKS_MAX`, this is a direct out-of-bounds read on a stack/heap buffer, depending on how `DecoderState` is allocated.

```c
static int same_segment(const DecoderState *d, int block_a, int block_b)
{
    seg_id_t a = d->block_segment[block_a];  // no bounds check
    seg_id_t b = d->block_segment[block_b];  // no bounds check
    ...
}
```

While `segment_begin()` does validate `mb >= 0 && mb < d->block_count` for writes, this read-side function has no equivalent guard.

---

## Summary

| # | Issue | Type | Severity | Line |
|---|---|---|---|---|
| 1 | `unsigned` counter truncated to `uint16_t`, collides with `SEG_NONE` sentinel at 65535 and wraps at 65536 | Integer truncation / sentinel collision | High | `seg->id = ++d->segment_counter;` |
| 2 | No bounds check on `block_a` / `block_b` in `same_segment()` | Out-of-bounds read | Medium | `d->block_segment[block_a]` |

The primary vulnerability is the integer truncation. An attacker with control over the bitstream can force segment IDs to collide with the `SEG_NONE` sentinel or with previously-assigned segment IDs, corrupting loop-filter boundary decisions for the decoded frame.

## Result

Pass.

Found it — yes. Correct line, correct mechanism.
Root cause — yes, fully. unsigned counter truncated into uint16_t seg_id_t, value 65535 = 0xFFFF = SEG_NONE, blocks written with that id, same_segment() then misreads them as unassigned → wrong loop-filter boundary decisions. The complete chain, with the consumer correctly identified as the thing that turns the collision into impact.
Impact — yes. Attacker controls segment count and block placement; 65535 segments is reachable; consequence is wrong cross-boundary filtering. Covers the reachability axis too.
Fix — this is the cleanest fix of any output so far, and it's nearly correct but has a subtle bug. It proposes if (d->segment_counter >= SEG_NONE - 1) return -1; before the increment. Walk it: SEG_NONE - 1 = 0xFFFE = 65534. At segment_counter == 65534 the check fires and rejects, so the increment never runs and the largest surviving id is 65533 (0xFFFD). That over-rejects by one — it needlessly throws away the perfectly safe id 0xFFFE. The correct guard is >= SEG_NONE - 1... no: to keep 0xFFFE usable you want the check to fire only when the next increment would produce 0xFFFF, i.e. if (d->segment_counter >= 0xFFFE) return -1; (equivalently >= SEG_NONE, since the pre-increment makes 0xFFFE the largest safe input). So the model is off by one in the safe direction — it errs toward rejecting too much, not too little. That's a far better failure than 5b's trap (which reintroduces the collision), but it's still not a perfect fix, and the model doesn't articulate the pre-increment reasoning that would have pinned the constant exactly.
