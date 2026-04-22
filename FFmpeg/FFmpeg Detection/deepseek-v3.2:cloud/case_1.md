# Security Vulnerability Analysis: `h264_slice_init`

## Vulnerability Type
**Integer overflow leading to sentinel value collision**

## Root Cause
The function unconditionally increments `h->current_slice` (an `int`) for each processed slice:
```c
sl->slice_num = ++h->current_slice;
```

When an attacker supplies more than `INT_MAX` (2,147,483,647) slices in a single access unit, `h->current_slice` will eventually overflow, wrapping to negative values. When `h->current_slice` reaches `-1`, `sl->slice_num` becomes `-1`.

## Exploitation Path
1. `sl->slice_num` (`int -1`) is stored into `h->slice_table` (a `uint16_t` array) elsewhere in the codebase
2. The assignment `h->slice_table[mb_pos] = sl->slice_num` implicitly casts the `int -1` to `uint16_t`, resulting in value `65535` (`0xFFFF`)
3. `0xFFFF` is exactly the **sentinel value** used to mark spare entries (`mb_x == mb_width`) and to indicate "no slice" in neighbor checks

## Defeated Safety Check
Downstream functions (like `fill_decode_caches`, `xchg_mb_border`) use the sentinel to decide whether a neighboring macroblock belongs to the current slice:
```c
if (h->slice_table[neighbor] != 0xFFFF) {
    /* neighbor belongs to current slice */
}
```

With slice index `65535` (`0xFFFF`), this check becomes `if (65535 != 65535)` → `false`, causing the decoder to incorrectly treat macroblocks from the same slice as belonging to a different slice.

## Impact
- **Memory corruption**: Incorrect slice boundary detection may cause out-of-bounds reads/writes in decoder operations
- **Logic errors**: Macroblocks may exchange data with wrong neighbors or use incorrect reference frames
- **Potential RCE**: In worst case, could be leveraged for arbitrary code execution via heap corruption

## Severity
**High** – Allows an attacker to corrupt decoder state with controlled input, potentially leading to remote code execution.

## Trigger Condition
1. Attacker crafts an H.264 bitstream containing >2.1 billion slice NAL units
2. All slices must be in the same access unit (same decoded picture)
3. The decoder must process all slices without resetting `h->current_slice` between pictures

## Attack Feasibility
While 2.1 billion slices is impractical in a real video stream, the vulnerability demonstrates a **theoretical boundary violation**. In practice, an attacker might:
- Combine with other vulnerabilities that allow resetting `h->current_slice` to near `INT_MAX`
- Use specially crafted streams that trigger rapid slice counter increments
- Exploit on 32-bit systems where `INT_MAX` is reachable with moderate resource consumption

## Mitigation
Add overflow check before increment:
```c
if (h->current_slice == INT_MAX) {
    av_log(h->avctx, AV_LOG_ERROR, "slice count overflow\n");
    return AVERROR_INVALIDDATA;
}
sl->slice_num = ++h->current_slice;
```

Alternatively, use `unsigned int` for `current_slice` and mask with `(MAX_SLICES-1)` consistently, treating it as a circular buffer index rather than an unbounded counter.