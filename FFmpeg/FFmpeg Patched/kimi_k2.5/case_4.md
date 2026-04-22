# Patch Assessment: FFmpeg H.264 slice_num Bounds Check

## Executive Summary

The patched version of `h264_slice_init` adds a bounds check before incrementing `h->current_slice`. This analysis traces whether the patch successfully prevents the `0xFFFF` sentinel collision vulnerability.

---

## 1. Can `(uint16_t)sl->slice_num` Still Equal `0xFFFF`?

### Trace of Execution

The patch adds:
```c
if (h->current_slice >= 0xFFFE) {
    av_log(h->avctx, AV_LOG_ERROR, "Too many slices (%d)\n",
           h->current_slice + 1);
    return AVERROR_PATCHWELCOME;
}
sl->slice_num = ++h->current_slice;
```

### Value Range Analysis

Let `cs` represent `h->current_slice` before the check:

| cs Before Check | Check Result | cs After `++cs` | `sl->slice_num` | `(uint16_t)sl->slice_num` |
|-----------------|--------------|-----------------|-----------------|---------------------------|
| 0 to 65533 (0xFFFD) | Pass | 1 to 65534 (0xFFFE) | 1 to 65534 | 1 to 65534 |
| 65534 (0xFFFE) | **FAIL** | Not reached | Not reached | Not reached |
| >= 65535 (0xFFFF+) | **FAIL** | Not reached | Not reached | Not reached |

### Maximum Reachable Value

**`h->current_slice` can reach a maximum of 65534 (0xFFFE) before the check.**

After the increment:
- `h->current_slice` becomes 65535 (0xFFFF)
- `sl->slice_num = 65535`
- `(uint16_t)sl->slice_num = 65535` (0xFFFF)

### Answer: **YES, `0xFFFF` is still reachable**

The check at `>= 0xFFFE` blocks when `current_slice` is 65534, but the increment happens **after** the check. This means:
- `current_slice` enters at 65534
- Check **fails** (returns error)
- But if the check were off-by-one, the increment would produce 65535

Wait - let me re-examine. The check `>= 0xFFFE` means:
- When `current_slice = 65534`: condition is TRUE, returns error
- So the maximum value that passes is `current_slice = 65533`
- After increment: `slice_num = 65534`

Therefore:
- **Maximum `sl->slice_num` reachable: 65534 (0xFFFE)**
- **`0xFFFF` (65535) is NOT reachable as `sl->slice_num`**

**However** - the sentinel collision occurs when `(uint16_t)slice_num == 0xFFFF`. If `sl->slice_num` maxes at 65534, then `(uint16_t)65534 = 0xFFFE ≠ 0xFFFF`.

**Conclusion: The sentinel collision at exactly `0xFFFF` is prevented.**

---

## 2. Threshold `0xFFFE` vs `0xFFFF`: Off-by-One Analysis

### The Code

```c
if (h->current_slice >= 0xFFFE) {  // 65534
```

### Question: Should it be `0xFFFF` instead?

### Analysis

If threshold were `0xFFFF` (65535):
- `current_slice = 65534` would **pass** the check
- After `++current_slice`: `slice_num = 65535` (0xFFFF)
- `(uint16_t)65535 = 0xFFFF` → **SENTINEL COLLISION!**

With current threshold `0xFFFE` (65534):
- `current_slice = 65534` **fails** the check
- Maximum that passes: `current_slice = 65533`
- After increment: `slice_num = 65534` (0xFFFE)
- `(uint16_t)65534 = 0xFFFE ≠ 0xFFFF` → **NO COLLISION**

### Verdict: **INTENTIONAL and CORRECT**

The threshold `0xFFFE` is **deliberately conservative**. The developer understood that:
1. The increment happens AFTER the check
2. Checking at `0xFFFE` prevents `slice_num` from ever becoming `0xFFFF`
3. This creates a 1-value safety margin before the sentinel

This is **NOT** an off-by-one bug - it's correct defensive programming.

---

## 3. Negative Value Bypass via Signed Integer

### The Vulnerability Class

`h->current_slice` is declared as `int` (signed 32-bit). Could a negative value bypass the check?

### Trace with Negative Values

| `h->current_slice` | Check: `>= 0xFFFE` | Result | After `++cs` | `(uint16_t)` cast |
|-------------------|-------------------|--------|-------------|-------------------|
| -1 | -1 >= 65534? | **FALSE** | 0 | 0 |
| -100 | -100 >= 65534? | **FALSE** | -99 | 0xFF9D (65437) |
| -2147483648 (INT_MIN) | INT_MIN >= 65534? | **FALSE** | -2147483647 | 0x0001 |

### Key Observation

**All negative values pass the check** because:
- In C, signed comparison: negative < positive
- `-1 >= 65534` evaluates to FALSE
- Any negative value is less than 65534

### Does This Produce `0xFFFF`?

For `sl->slice_num` to equal 65535 (0xFFFF), we need:
```
++h->current_slice == 65535
h->current_slice (before) == 65534
```

But `65534 >= 0xFFFE` is TRUE, so this is blocked.

### What About Integer Overflow?

Could overflow from a large positive value wrap to negative, then later reach 65535?

**Scenario:**
1. `current_slice` starts at 0, increments normally
2. Eventually: `current_slice = 2147483647` (INT_MAX)
3. Next slice: `++current_slice` overflows to `-2147483648` (INT_MIN) - **UB in C**
4. Now `current_slice = -2147483648`
5. Check: `-2147483648 >= 65534` → FALSE (passes!)
6. After increment: `-2147483647`
7. Continue until... can we reach 65535?

**Problem:** After overflow to negative, `current_slice` would need to increment from INT_MIN up to 65534 to trigger the check. That's 2,147,483,647 + 65534 = ~2.1 billion increments. 

But the check happens **every slice**. The values while negative would be:
- `-2147483648` → passes (returns error would need cs >= 65534)
- ...increments toward 0...
- `-1` → passes (still less than 65534)
- `0` → passes
- ...continues to 65533 → passes
- `65534` → **FAILS** (blocks here)

### Conclusion: **Negative values do NOT bypass to reach 0xFFFF**

The overflow scenario doesn't help because:
1. Overflow from INT_MAX → INT_MIN requires 2+ billion slices (already large file)
2. After overflow, the counter must climb back to 65534 to be blocked
3. But it can never produce `slice_num = 65535` because the check at 65534 blocks before the increment that would produce 65535

---

## 4. Overall Verdict

### Is the Patch Effective?

| Attack Vector | Original Code | Patched Code | Status |
|---------------|---------------|--------------|--------|
| `slice_num = 65535` via normal increment | Possible at 65535th slice | **Blocked** - check at 65534 | ✅ Fixed |
| Signed overflow wrapping | Could reach any value | Check still catches at 65534 | ✅ Fixed |
| Integer overflow from negative | N/A (would hit 65534 check) | Blocked at 65534 | ✅ Fixed |

### Formal Proof of Safety

**Theorem:** After the patch, `(uint16_t)sl->slice_num` can never equal `0xFFFF` (65535).

**Proof:**

1. Let `cs` be `h->current_slice` before the patched check
2. The check requires: `cs < 0xFFFE` (65534) to pass
3. Therefore: `cs <= 0xFFFD` (65533) is the maximum passing value
4. After increment: `sl->slice_num = cs + 1 <= 65534` (0xFFFE)
5. Maximum `sl->slice_num = 65534`
6. `(uint16_t)65534 = 0xFFFE ≠ 0xFFFF`
7. ∎ The sentinel value `0xFFFF` is unreachable

### Potential Residual Issues

While the sentinel collision is fixed, consider:

1. **`slice_row` and `ref2frm` indexing:**
   ```c
   h->slice_row[(sl->slice_num-1)&(MAX_SLICES-1)]
   ```
   With `slice_num` max 65534, masking with 127 gives index 126. This is within bounds.

2. **`slice_table` storage:**
   The actual storage of `slice_num` into `slice_table` (uint16_t) would store `0xFFFE`, which is safe.

3. **Array size limits:**
   `MAX_SLICES` is typically 128. The warning at `sl->slice_num >= MAX_SLICES` would fire at slice 128+, but the new check prevents reaching that.

### Edge Case: Maximum Slices Per Frame

The check triggers error at slice 65535 (when `current_slice = 65534`). This is:
- Far below `INT_MAX` (2 billion)
- Far above realistic H.264 use cases (typically < 100 slices)
- Reasonable for a safety limit

---

## Summary

| Question | Answer |
|----------|--------|
| **Can `0xFFFF` be reached?** | **NO** - Maximum reachable `slice_num` is 65534 (0xFFFE) |
| **Is `0xFFFE` threshold correct?** | **YES** - Intentionally conservative, prevents off-by-one |
| **Can negative values bypass?** | **NO** - All negative values pass, but increment can never produce 65535 (checked at 65534) |
| **Is patch effective?** | **YES** - The sentinel collision vulnerability is **FIXED** |

### Final Verdict

**The patched code is SAFE from the `0xFFFF` sentinel collision vulnerability.**

The patch correctly:
1. Prevents `sl->slice_num` from ever equaling `0xFFFF`
2. Uses an appropriately conservative threshold (`0xFFFE` vs `0xFFFF`)
3. Is not bypassable via signed integer tricks or overflow

**CVSS Impact:** With this patch, the vulnerability is **REMEDIATED**.
