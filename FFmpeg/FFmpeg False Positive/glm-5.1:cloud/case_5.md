---
name: case_5
description: Evaluation of the masked slice‑counter implementation and the static‑analysis finding about a sentinel collision.
type: project
---

## 1. Values that `slice_ctr` can take
`compute_slice_num` performs:
```c
uint16_t slice_ctr = (uint16_t)(h->current_slice & 0x7FFF);
```
* `h->current_slice` is a signed `int`.
* The `& 0x7FFF` operation promotes the left‑hand operand to **unsigned int** before the bitwise AND (C integer‑promotion rules).  Negative values are first converted to a large unsigned representation, but **only the low 15 bits** are kept because the mask is `0x7FFF`.
* Therefore the result of the mask is an integer in the range **0 … 0x7FFF** (0 … 32767).
* The cast to `uint16_t` does not change that range.
* The subsequent guard:
```c
if (slice_ctr == 0)
    slice_ctr = 1;
```
ensures the final value is **1 … 0x7FFF**.

**Maximum value:** `0x7FFF` (32767).  The sentinel stored in `slice_table` is `0xFFFF` (65535).  Consequently `slice_ctr` can *never* equal `0xFFFF`.

## 2. Is the mask “insufficient”?
The analysis tool claims that masking with `0x7FFF` is insufficient to prevent `(uint16_t)slice_ctr` from reaching `0xFFFF`.

Let us examine concrete bit patterns:
| `h->current_slice` (hex) | Binary (32 bit)                     | `h->current_slice & 0x7FFF` (hex) | Result (`uint16_t`) |
|---------------------------|------------------------------------|-----------------------------------|----------------------|
| `0x00000000`              | `0000…0000`                        | `0x0000`                           | `0x0000` (then -> 1) |
| `0x00007FFF`              | `0000 0111 1111 1111 1111`          | `0x7FFF`                           | `0x7FFF` |
| `0x00008000`              | `0000 1000 0000 0000 0000`          | `0x0000`                           | `0x0000` (then -> 1) |
| `0xFFFFFFFF` (‑1)        | `1111…1111`                         | `0x7FFF` (low 15 bits are all 1)   | `0x7FFF` |
| `0x80007FFF` (large positive) | `1000 0000 0000 0111 1111 1111 1111` | `0x7FFF`                           | `0x7FFF` |

In **every** case the masked value is limited to the 15‑bit range.  The only way to obtain `0xFFFF` would be to have the low 16 bits all set, which the mask explicitly clears the high bit (bit 15).  Hence the mask is *more than sufficient* to prevent the sentinel value.

## 3. Safety‑valve `if (slice_ctr == 0) slice_ctr = 1`
*Purpose*: `slice_table` uses `0` as an “un‑initialised” marker in the original FFmpeg code, so the developers wanted to avoid storing `0` in the table.

Effect:
- If `h->current_slice & 0x7FFF` yields `0` (this happens for any `h->current_slice` that is a multiple of `0x8000`), the function substitutes `1`.
- `1` is a perfectly valid slice number (the first real slice gets `1` after this fix).

Potential issues:
- **Duplicate slice numbers**: because of the mask, after `0x7FFF` the counter wraps to `0` → `1`.  Two different logical slices will receive the same `slice_num`.  This can confuse algorithms that rely on monotonic slice numbers (e.g., `h->slice_row` indexing, deblocking neighbour checks).  The result is **functional incorrectness** (wrong deblocking decisions, possible visual artifacts), but it does **not** re‑introduce the sentinel collision.
- **Zero‑value handling**: The guard guarantees the stored value is never `0`, so it does not create a new sentinel conflict.
- **No security impact**: Even if duplicate slice numbers cause logic errors, they do not give the attacker a write primitive or memory‑corruption primitive.

Thus the safety‑valve is harmless from a security viewpoint.

## 4. Final verdict – is the code vulnerable to the sentinel collision?
**No.** The combination of:
1. A 15‑bit mask (`& 0x7FFF`) that guarantees the result is ≤ 0x7FFF, and
2. A post‑mask check that replaces a possible `0` with `1`
ensures that the value stored in `slice_table` can never be `0xFFFF`, the sentinel used by the deblocking code.

### Other observations worth noting
- **Logical wrap‑around**: After 32767 slices the counter restarts at `1`.  In a well‑formed H.264 stream this never happens (the spec limits slice count far below this).  In a malicious stream an attacker could force the wrap‑around, causing duplicate slice numbers and potentially breaking deblocking heuristics, leading to visual corruption or a denial‑of‑service, but **no arbitrary memory write**.
- **Signed‑overflow undefined behaviour**: `h->current_slice` is a signed `int`.  If an attacker could cause it to exceed `INT_MAX` the increment would invoke signed overflow, which is undefined.  Achieving more than ~2 billion slices in a single picture is infeasible, so this is not a realistic concern.
- **Masking a signed value**: The mask operation implicitly converts the signed operand to unsigned, which is well‑defined.  No surprising sign‑extension issues arise.

### Recommendation
If the goal is to keep slice numbers strictly monotonic and avoid any duplicate‑slice side‑effects, replace the masking with a **saturating check** that aborts when the counter would exceed a safe maximum (e.g., `if (h->current_slice >= MAX_SLICES) return error;`).  This would preserve functional correctness while still preventing the sentinel collision.

---
*Security impact*: **None** – sentinel collision mitigated.
*Functional impact*: Possible wrap‑around after 32767 slices; unlikely in normal operation but could be a DoS vector in a crafted stream.
