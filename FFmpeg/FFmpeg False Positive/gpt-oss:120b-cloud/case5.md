# False‑Positive Assessment of the Masked Slice Counter

## 1. Value range of `slice_ctr`
`slice_ctr` is computed as:
```c
uint16_t slice_ctr = (uint16_t)(h->current_slice & 0x7FFF);
```
- `0x7FFF` is binary `0111 1111 1111 1111`, i.e. the lower 15 bits set to 1.
- The bit‑wise AND clears bit 15 (the most‑significant bit of a 16‑bit value) and keeps bits 0‑14.
- Consequently the result is always in the range **0 … 0x7FFF (32767)**.
- After the optional safety‑valve the only possible values are **1 … 0x7FFF** (zero is replaced by one). 
- **`0xFFFF` (65535) can never be produced** because bit 15 is always forced to 0 before the cast.

## 2. Is the mask “insufficient”?
The static‑analysis claim suggests that masking with `0x7FFF` does not stop the value from reaching `0xFFFF`. This is inaccurate:
- Any 16‑bit number equal to `0xFFFF` has bits `1111 1111 1111 1111`. After `& 0x7FFF` the result becomes `0x7FFF` (`0111 1111 1111 1111`).
- The mask therefore **guarantees** that the most‑significant bit is cleared, removing the possibility of `0xFFFF`.
- Concrete example:
  - If `h->current_slice = 0xFFFF`, then `h->current_slice & 0x7FFF = 0x7FFF`.
  - If `h->current_slice = 0x8000`, the result is `0x0000` (later changed to `1`).
Thus the mask is sufficient to keep the value below the sentinel.

## 3. Effect of the safety‑valve `if (slice_ctr == 0) slice_ctr = 1`
- The only way `slice_ctr` can be zero is when the lower 15 bits of `h->current_slice` are all zero, i.e. `h->current_slice & 0x7FFF == 0`.
- This occurs for values like `0x0000`, `0x8000`, `0x10000` (if `int` is larger than 16 bits), etc.
- Mapping zero to `1` merely avoids storing `0` in `slice_table`. The downstream deblocking logic treats `0` as “uninitialized” (the original FFmpeg code uses 0 as a special value). Replacing it with `1` does **not** re‑introduce the sentinel (`0xFFFF`).
- The change may affect correctness (e.g., it shifts slice numbering by one for those edge cases), but it does **not** create a new security issue.

## 4. Verdict
- **Sentinel collision:** The implementation **cannot** produce `0xFFFF`; the mask guarantees the high bit is cleared, and the safety‑valve only changes a possible `0` to `1`. Therefore the static‑analysis finding of a high‑severity sentinel collision is a **false positive**.
- **Other concerns:** The only noteworthy point is a potential functional deviation: when `h->current_slice`'s low 15 bits are zero the decoder will treat the slice as number 1 instead of 0, which could affect slice‑ordering logic that expects the first slice to be 0. From a security perspective, this is benign.

---
*Analysis performed solely from the supplied source; no external references were used.*