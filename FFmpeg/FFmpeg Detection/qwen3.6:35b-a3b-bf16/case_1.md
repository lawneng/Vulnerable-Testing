# H.264 Slice Init — Security Vulnerability Assessment

## Vulnerability: Silent Slice Num Wraparound (CWE-190: Integer Overflow)

### Severity: HIGH

### Bug Type

Integer overflow in `h->current_slice` combined with a **logic bug in the overflow detection** that causes the check to be completely bypassed at the wrap boundary.

### Root Cause

```c
sl->slice_num = ++h->current_slice;  // unconditionally incremented

if (sl->slice_num)
    h->slice_row[(sl->slice_num-1)&(MAX_SLICES-1)] = sl->resync_mb_y;
if (   h->slice_row[sl->slice_num&(MAX_SLICES-1)] + 3 >= sl->resync_mb_y
    && h->slice_row[sl->slice_num&(MAX_SLICES-1)] <= sl->resync_mb_y
    && sl->slice_num >= MAX_SLICES) {
    av_log(..., "Possibly too many slices...");
}
```

`h->current_slice` is a plain `int` incremented unconditionally for every slice header parsed. `sl->slice_num` is then masked with `(MAX_SLICES - 1)` (typically 127) when used as an index.

### Trigger Condition

An attacker crafts an H.264 bitstream containing **128 or more slice NAL units** in a single access unit. When `h->current_slice` reaches 128, the masking `sl->slice_num & (MAX_SLICES-1)` wraps it to **0**.

### Why the Check Is Defeated

The `if (sl->slice_num)` guard at the assignment is a **truthiness check** that gates the update. When `sl->slice_num` wraps to 0:

1. **Assignment is skipped** — `if (sl->slice_num)` evaluates to false. The entry at index 0 is not updated to the new slice's row. Instead, the stale value from 128 slices ago remains.
2. **Warning check is bypassed** — The overflow warning requires `sl->slice_num >= MAX_SLICES` (128). But `sl->slice_num` is now 0, so this condition is false. The warning never fires.

The overflow check fires for slice numbers 128, 129, ..., 255 but **not at 0** (the wrap point). By slice 256, the damage (stale `slice_row` entries) has already been done.

### Downstream Impact

- **`h->slice_row` corruption**: Downstream functions like `fill_decode_caches` and `xchg_mb_border` use `slice_row` to determine whether neighboring macroblocks belong to the current slice. A stale entry causes the decoder to treat MBs from a previous slice cycle as belonging to the current slice, defeating inter-slice boundary checks.
- **`h->ref2frm` collision**: The same masking wraps `ref2frm` indices, causing reference frame mapping from one slice cycle to corrupt another.
- **Memory safety**: Incorrect neighbor classification can lead to out-of-bounds reads when the decoder accesses reference data for what it believes is a valid neighboring MB.

### Exploit Scenario

1. Attacker crafts an H.264 bitstream with 128+ slices in a single frame
2. Decoder processes slices 0-127 normally, populating `slice_row` and `ref2frm`
3. Slice 128 wraps `slice_num` to 0 — the row assignment is skipped, and the old value at index 0 persists
4. For slices 129-255, the collision at index 1 continues (each overwrites the previous cycle's entry)
5. Spatial prediction in later slices reads stale `slice_row` data, misidentifying neighbor relationships

### Recommended Fix

Use a separate counter for the index rather than gating on `sl->slice_num`'s truthiness:

```c
int slice_idx = sl->slice_num & (MAX_SLICES - 1);
h->slice_row[slice_idx] = sl->resync_mb_y;

// Overflow check should be based on the actual slice number, not the masked index
if (h->current_slice >= MAX_SLICES) {
    int prev_row = h->slice_row[slice_idx];
    if (prev_row + 3 >= sl->resync_mb_y && prev_row <= sl->resync_mb_y) {
        av_log(..., "Possibly too many slices (%d >= %d)...\n",
               sl->slice_num, MAX_SLICES);
    }
}
```

Or use an unsigned 32-bit counter for `h->current_slice` with modulo arithmetic, and always perform the update regardless of the masked index value.
