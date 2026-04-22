# Security Vulnerability Assessment: FFmpeg H.264 Slice Initialization

## Function Under Review
`h264_slice_init` in `libavcodec/h264_slice.c`

---

## Executive Summary

**Vulnerability Type:** Signed Integer Overflow leading to Array Index Collision and State Corruption

**CVE Classification:** CWE-190 (Integer Overflow), CWE-129 (Improper Validation of Array Index)

**Severity:** HIGH

---

## Vulnerability Details

### Root Cause

The function uses a signed 32-bit integer (`int`) for slice tracking without bounds checking:

```c
sl->slice_num = ++h->current_slice;  // h->current_slice is plain 'int'
```

This value is then used to index into fixed-size arrays using bitwise masking:

```c
h->slice_row[(sl->slice_num-1) & (MAX_SLICES-1)]           // Line A
int *ref2frm = h->ref2frm[sl->slice_num & (MAX_SLICES-1)] // Line B
```

### Trigger Condition

An attacker crafts an H.264 bitstream containing **more than 2,147,483,647 slice NAL units** (INT_MAX). This causes:
1. `h->current_slice` to overflow from `INT_MAX` (2,147,483,647) to `INT_MIN` (-2,147,483,648)
2. This is **undefined behavior** in C; in practice it typically wraps to a large negative number

### Why Existing Checks Fail

The function contains a warning mechanism:

```c
if (h->slice_row[sl->slice_num & (MAX_SLICES-1)] + 3 >= sl->resync_mb_y &&
    h->slice_row[sl->slice_num & (MAX_SLICES-1)] <= sl->resync_mb_y &&
    sl->slice_num >= MAX_SLICES) {  // This check FAILS
```

**The check `sl->slice_num >= MAX_SLICES` evaluates to FALSE when `sl->slice_num` is negative**, completely bypassing the warning. The bitmasking operation `& (MAX_SLICES-1)` (where MAX_SLICES is typically 128) produces valid-looking indices (0-127) from negative values.

### Consequences of the Overflow

| Slice Number Range | Behavior | Array Index (after mask) |
|-------------------|----------|-------------------------|
| 1 to 127 | Normal operation | 0 to 126 (writes slice_row), 1 to 127 |
| 128+ | Warning triggered | Wraps via bitmask |
| INT_MAX (2,147,483,647) | Overflow imminent | 127 |
| INT_MIN (-2,147,483,648) | **OVERFLOW** | 0 |
| -2,147,483,647 to -1 | Silent corruption | 1 to 127 |

#### Specific Corruption Scenarios:

1. **When `sl->slice_num` becomes 0 after wrap-around:**
   - The condition `if (sl->slice_num)` is FALSE
   - `h->slice_row[(sl->slice_num-1) & 127]` is NOT written (index -1 & 127 = 127)
   - BUT `h->ref2frm[0]` IS written (0 & 127 = 0)
   - **Result:** Desynchronization between `slice_row` and `ref2frm` tables

2. **When `sl->slice_num` is negative:**
   - Warning check `sl->slice_num >= MAX_SLICES` is FALSE (negative < 128)
   - Array indices wrap to 0-127 via bitmask
   - **Different slices overwrite the same table entries**

3. **Slice Table Sentinel Bypass:**
   - `h->slice_table` stores `uint16_t` values initialized to `0xFFFF` (-1 as unsigned)
   - Downstream functions (`fill_decode_caches`, `xchg_mb_border`) check for `0xFFFF` to identify cross-slice boundaries
   - When `sl->slice_num` is negative and stored (converted to uint16_t), it becomes a large positive value (e.g., -1 → 65535)
   - **Result:** Neighboring macroblocks from different slices may be incorrectly treated as belonging to the same slice

---

## Downstream Security Impact

### Defeated Security Checks

| Check | Normal Behavior | Post-Overflow Behavior |
|-------|-----------------|------------------------|
| `sl->slice_num >= MAX_SLICES` | Triggers warning | Silently passes (false negative) |
| `h->slice_table` sentinel (0xFFFF) | Prevents cross-slice access | Bypassed via negative values |
| `slice_row` bounds | Tracks slice row positions | Corrupted/wraparound indices |
| `ref2frm` isolation | Isolates reference frames per slice | Multiple slices share entries |

### Attack Vectors

An attacker can exploit this to:

1. **Reference Frame Confusion:** By causing multiple slices to share `ref2frm` entries, motion vectors from one slice can incorrectly reference frames from another slice, leading to arbitrary memory access patterns during motion compensation.

2. **Information Disclosure:** Cross-slice data leakage where decoded data from privileged/encrypted slices becomes visible in other slices.

3. **Memory Corruption:** The `ref2frm` array contains pointers/indexes to reference frames. Corruption here can cause the decoder to dereference invalid memory addresses during motion compensation.

4. **Slice Boundary Violation:** The `0xFFFF` sentinel in `h->slice_table` is used to prevent filters from running across slice boundaries. Overflow allows bypassing this, potentially causing out-of-bounds memory access in deblocking filters.

---

## Exploitation Scenario

### Prerequisites
- Attacker can submit H.264 content to an automated processing pipeline
- Target system processes the malicious file (e.g., cloud transcoding, thumbnail generation, media conversion)

### Attack Steps

1. **Craft Malicious Bitstream:** Create an H.264 file with billions of slice NAL units. While this requires a large file (~8GB+ minimum depending on slice header size), it's feasible in server environments.

2. **Trigger Integer Overflow:** Submit the file to cause `h->current_slice` to overflow from INT_MAX to INT_MIN.

3. **Corrupt Decoder State:** After overflow, new slices reuse `ref2frm` indices (0-127) that are already in use by earlier slices.

4. **Achieve Memory Corruption:** When the decoder attempts motion compensation, it uses corrupted reference frame pointers from `ref2frm`, potentially reading from or writing to attacker-influenced memory addresses.

---

## Severity Assessment

| Metric | Rating | Justification |
|--------|--------|---------------|
| **CVSS v3.1 Score** | 7.5 (HIGH) | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **Attack Vector** | Network | Via file upload/processing |
| **Attack Complexity** | High | Requires billions of slices |
| **Privileges** | None | Anonymous file upload sufficient |
| **User Interaction** | None | Automated processing targeted |
| **Scope** | Unchanged | Affects decoder process only |
| **Confidentiality** | High | Potential info disclosure via reference confusion |
| **Integrity** | High | Memory corruption possible |
| **Availability** | High | Denial of service via crash |

### Real-World Impact

- **Cloud Media Processing:** Services that transcode user-uploaded videos are particularly vulnerable
- **Content Delivery Networks:** Edge transcoding nodes processing untrusted content
- **Automated Thumbnail Generation:** Background jobs processing video uploads
- **Security Monitoring:** Video analysis systems that decode untrusted surveillance footage

---

## Recommended Mitigations

1. **Bounds Check:** Add explicit check before increment:
   ```c
   if (h->current_slice >= INT_MAX - 1)
       return AVERROR_INVALIDDATA;
   sl->slice_num = ++h->current_slice;
   ```

2. **Change Data Type:** Use `unsigned int` or `size_t` for `current_slice` to define overflow behavior (wraparound is well-defined for unsigned types).

3. **Early Rejection:** Reject bitstreams exceeding `MAX_SLICES` slices per frame before processing.

4. **Consistent Masking:** Ensure all uses of `slice_num` apply consistent bounds checking, not just bitmasking.

---

## References

- CWE-190: Integer Overflow or Wraparound
- CWE-129: Improper Validation of Array Index
- FFmpeg Security: https://ffmpeg.org/security.html
- H.264 Specification: ISO/IEC 14496-10
