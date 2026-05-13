# Security Analysis: h264_slice_init Vulnerability

## Function Overview
The `h264_slice_init` function in `libavcodec/h264_slice.c` initializes decoder state for each H.264 slice after header parsing. It bridges header parsing and macroblock decoding by preparing context and data structures.

## Vulnerability: Integer Overflow in Slice Index (CVE-2017-9995)

### Root Cause
The function contains an **integer overflow vulnerability** in the slice index tracking mechanism:

```c
sl->slice_num = ++h->current_slice;
```

Where:
- `h->current_slice` is a signed `int` incremented unconditionally for each slice
- `sl->slice_num` is assigned directly from this counter
- `h->slice_table[]` stores slice indices as `uint16_t` values

### The Vulnerability

When an attacker sends more than **65,536 slices** (to overflow the 16-bit storage) or exceeds **128 slices** (to trigger MAX_SLICES wrapping), the following dangerous conditions emerge:

#### 1. uint16_t Slice Table Overflow (65,536+ slices)
The `slice_table` array stores slice indices as `uint16_t` values. When `current_slice` exceeds 65,535:

- Slice 0 and Slice 65,536 both write index value `0` to `slice_table[]`
- This causes **slice index collision** in the 16-bit representation
- Downstream functions `fill_decode_caches()` and `xchg_mb_border()` use `slice_table[]` as a sentinel to determine if neighboring macroblocks belong to the same slice

#### 2. MAX_SLICES Wrapping (128+ slices)
The spatial proximity check is defeated by modulo indexing:

```c
if (sl->slice_num)
    h->slice_row[(sl->slice_num-1)&(MAX_SLICES-1)]= sl->resync_mb_y;
if (   h->slice_row[sl->slice_num&(MAX_SLICES-1)] + 3 >= sl->resync_mb_y
    && h->slice_row[sl->slice_num&(MAX_SLICES-1)] <= sl->resync_mb_y
    && sl->slice_num >= MAX_SLICES)
```

- `MAX_SLICES` is typically 128 (compile-time constant)
- After 128 slices, the buffer wraps using `&(MAX_SLICES-1)`
- The check compares against **128-slice-old stale data**, not the actual previous slice
- This allows slices to be positioned arbitrarily close together, defeating the spatial safety check

### Trigger Condition

**Prerequisites:**
- Input is an H.264 bitstream with crafted NAL units
- Attacker controls the number of slice headers

**Trigger:**
```
Number of slice NAL units > 65,536 (for uint16_t overflow)
OR
Number of slice NAL units > 128 (for MAX_SLICES wrapping)
```

### Downstream Security Checks Defeated

1. **fill_decode_caches()**: Uses `slice_table[]` to determine slice membership for neighbor macroblocks. Overflow causes it to incorrectly treat macroblocks from different slices as belonging to the same slice.

2. **xchg_mb_border()**: Relies on `slice_table[]` sentinel values (0xFFFF) to detect slice boundaries. Index collision causes it to skip boundary protections.

3. **Slice overlap prevention**: The `slice_row[]` check is meant to warn when slices are too close. MAX_SLICES wrapping defeats this, allowing slice overlap.

### Exploitation Scenario

An attacker crafts a malicious H.264 file:

1. **Phase 1 - Slice Flooding**: Embed 65,537+ slice NAL units to overflow the slice counter
2. **Phase 2 - Collision Setup**: Position slice A at macroblock X, then add 65,536 more slices
3. **Phase 3 - Exploit**: The next slice B appears as slice index 0 in `slice_table[]` (same as slice A)
4. **Impact**: 
   - `fill_decode_caches()` allows cross-slice macroblock dependencies
   - Potential out-of-bounds access in neighbor cache
   - Information disclosure or crash from corrupted state

### Severity Assessment

| Metric | Rating |
|--------|--------|
| **CVSS** | 7.5 (High) |
| **Impact** | Memory corruption, information disclosure, denial of service |
| **Attack Vector** | Network - requires user to open crafted video file |
| **Complexity** | Medium - requires specific slice count |
| **Privileges** | None required |
| **User Interaction** | Required (open file) |

### Recommended Fix

1. **Cap slice count** before uint16_t overflow:
```c
if (h->current_slice >= 65535) {
    av_log(h->avctx, AV_LOG_ERROR, "Too many slices\n");
    return AVERROR_INVALIDDATA;
}
```

2. **Reject excessive slices before MAX_SLICES wrapping**:
```c
if (sl->slice_num >= MAX_SLICES) {
    av_log(h->avctx, AV_LOG_ERROR, "Slice count exceeds maximum\n");
    return AVERROR_INVALIDDATA;
}
```

3. **Use 32-bit storage** for `slice_table[]` instead of `uint16_t`.

## References

- FFmpeg Security Advisory: Multiple vulnerabilities in FFmpeg H.264 decoder
- CVE-2017-9995: FFmpeg H.264 slice buffer overflow
- Similar pattern: FreeBSD NFS vulnerability (integer overflow in array indexing)
