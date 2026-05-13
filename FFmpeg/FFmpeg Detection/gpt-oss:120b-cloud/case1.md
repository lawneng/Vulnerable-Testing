# FFmpeg `h264_slice_init` Security Assessment

**Vulnerability:** Integer overflow of `h->current_slice` / `sl->slice_num`.

**Exact condition:** `h->current_slice` is an `int` that is incremented unconditionally for every parsed slice:
```c
sl->slice_num = ++h->current_slice;
```
If an attacker supplies a bitstream containing a very large number of slices (e.g., more than `INT_MAX` slices) the increment will overflow, wrapping the signed integer to a negative value (undefined‑behaviour in C). The subsequent indexing into the circular buffers:
```c
h->slice_row[(sl->slice_num-1)&(MAX_SLICES-1)] = sl->resync_mb_y;
ref2frm = h->ref2frm[sl->slice_num & (MAX_SLICES-1)][j];
```
relies on the value being non‑negative and within the range `[0, MAX_SLICES)`. After overflow the mask still yields a valid index, but `sl->slice_num` becomes negative, causing the sentinel logic that downstream functions (`fill_decode_caches`, `xchg_mb_border`) use to mis‑classify macroblocks from other slices as belonging to the current slice.

**Down‑stream impact:** The sentinel `0xFFFF` in `h->slice_table` tells the decoder whether a neighboring macroblock is part of the same slice. When the overflow corrupts `slice_num`, the sentinel check can be bypassed, allowing an attacker‑crafted slice to manipulate macroblock decoding of *other* slices. This can lead to:
- Out‑of‑bounds writes/read in macroblock processing (because the decoder assumes the macroblock belongs to the current slice).
- Memory corruption that may be exploitable for arbitrary code execution depending on surrounding code.
- Denial‑of‑service through crashes or malformed frames.

**Severity:** *High* – Integer overflow leads to undefined behaviour and can corrupt decoder state, potentially resulting in remote code execution when the vulnerable FFmpeg binary decodes attacker‑controlled video streams.

**Exploitation path:**
1. Craft an H.264 bitstream containing more than `INT_MAX` slice NAL units (or enough slices to wrap the 32‑bit signed counter).
2. Feed this stream to the vulnerable FFmpeg build.
3. The overflow changes `sl->slice_num` to a negative value, breaking the slice‑boundary sentinel.
4. Subsequent macroblock decoding can write outside the intended buffers, corrupting memory and possibly hijacking control flow.

**Mitigation recommendations:**
- Change `current_slice` and `slice_num` to an unsigned type with a defined wrap‑around semantics, and add a hard limit check (e.g., abort if slice count exceeds a safe threshold such as `MAX_SLICES` or a configurable maximum).
- Validate the slice count before incrementing and return an error if the limit is exceeded.
- Consider using `size_t` or `uint32_t` and explicitly mask the index without relying on signed overflow.

---
*Assessment performed without external references, based solely on the provided source.*