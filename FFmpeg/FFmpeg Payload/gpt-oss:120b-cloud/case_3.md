# Practical Exploitation: Delivery, Value Control, Grooming, and Info-Leak Path

## 1. Delivery: Getting 65536 Slices to the Decoder

### Transport Analysis

| Transport | Mechanism | Limit | Verdict |
|-----------|-----------|-------|---------|
| **Raw Annex B file** | Start-code-delimited NAL units, parsed directly by `h264_decode_frame` | None — parser imposes no slice count limit | **Best option** |
| RTSP/RTP | NAL units in RTP packets; FU-A for large NALs, single-packet for small | None inherent, but real-time buffering may drop packets under load | Feasible but fragile |
| HLS segment | Raw Annex B in `.ts` segments or fMP4 | TS has no slice limit; fMP4 sample tables may use uint16 counts | TS works; fMP4 risky |
| MP4/MKV container | Moov/mdat or EBML structure with sample tables | Many muxers reject >8192 slices; `stsz`/`stsc` overflow possible | **Unreliable** |
| WebRTC | SRTP with limited jitter buffer and strict RTCP feedback | Implementations typically cap slices per frame; not designed for this | **Not viable** |

### Most Reliable: Raw Annex B Bytestream

A raw Annex B file delivers slices directly to FFmpeg's H.264 parser without any container overhead. The parser (`h264_parse`) identifies access unit boundaries by NAL type and processes each slice sequentially. There is no code path that rejects an access unit for having too many slices — the only limit is available memory.

Each slice requires a minimum of:
- Start code: 4 bytes (`00 00 00 01`)
- Slice header: ~8–12 bytes (first_mb_in_slice, slice_type, PPS ID, frame_num, etc.)
- Minimal MB data: ~3–10 bytes (skip MB or I_PCM for 1 MB)

Total per slice: ~15–26 bytes. For 65536 slices: **~1–1.7 MB**. Entirely feasible as a file.

The H.264 parser assembles an access unit from consecutive NAL units until it detects an access unit delimiter or a new frame. With 65536 non-IDR slice NAL units and no access unit delimiters between them, the parser groups them into a single access unit and passes them to `h264_decode_frame` as a single packet.

**Delivery path for a local file:**
```
ffmpeg -i exploit.h264 -f null -    # direct decode
ffplay exploit.h264                  # playback
```

**Delivery path for a stream:** Encode as raw Annex B, serve over HTTP as `video/h264` or as an HLS segment with `codec=avc1` and raw Annex B payloads. The target's media pipeline must not re-mux into MP4 before decoding.

### Practical Concern: Memory and Processing

65,536 slice contexts consume significant memory. Each `H264SliceContext` is ~2–4 KB (depending on build). Total: ~128–256 MB. A 64-bit system can handle this, but 32-bit builds may exhaust address space. The exploit file should minimize per-slice overhead by using the simplest possible slice headers (I-slice, PPS 0, no weighted prediction, no deblocking).

---

## 2. Value Control: Controlling the 16 Bytes at the Underflow Offset

### The XCHG Primitive

`xchg_mb_border` swaps 16 bytes between the top border cache (`top_borders[top_idx][0..15]`) and the underflow address (`top_borders[top_idx][-1]`, resolving to -88 bytes). The value **written** to the underflow is the content of the top border cache, and the value **read** from the underflow is placed into the border cache.

The top border cache stores reconstructed luma pixel values from the macroblock row directly above the current macroblock. These values are populated during macroblock decoding of that row.

### I_PCM: Full Byte-Level Control

H.264's I_PCM macroblock type transmits raw pixel values directly in the bitstream, bypassing all prediction, transform, and entropy coding:

```
I_PCM MB in slice N-1, row R:
  mb_type = I_PCM (mb_type_num = 25 in I-slice)
  pcm_alignment_zero_bit
  pcm_sample_luma[256]   ← attacker sets each byte directly
  pcm_sample_chroma[128] ← attacker sets each byte directly
```

For 8-bit luma depth, each pixel is exactly one byte. The attacker writes the desired 16 bytes as the first 16 luma pixels of the I_PCM macroblock. After reconstruction, these bytes are stored in `top_borders` verbatim — no quantization, no transform, no prediction residual.

**Result: the attacker has full, arbitrary byte-level control over all 16 bytes written at the underflow offset.** This is sufficient to:
- Write a precise 64-bit pointer (8 bytes) with full control over each byte
- Write a tcache `next` pointer (8 bytes) with exact target address
- Write a glibc safe-linking XOR mask (requires knowing the chunk address — see Section 4)
- Write arbitrary metadata fields (size, fd, bk, etc.)

### Without I_PCM (CABAC/CAVLC modes)

For non-PCM modes, the attacker's control is indirect:

```
reconstructed_pixel = prediction + inverse_transform(dequant(coefficients))
```

- **Prediction:** Controllable (the attacker chooses the prediction mode and reference data)
- **Coefficients:** Controllable to within quantization error. With QP=0, quantization is lossless; the attacker specifies exact coefficient values. With higher QP, quantization introduces rounding.

At QP=0 with all-zero coefficients and DC prediction, each 4x4 block gets a uniform value equal to the DC coefficient. The attacker can set any value 0–255 per pixel, but the values must be uniform within each 4x4 block. Across the 16-pixel top border (4 blocks of 4 pixels), this gives 4 independently controllable values, each repeated 4 times.

At QP=0 with careful coefficient coding, the attacker can achieve arbitrary per-pixel values, but the CABAC/CAVLC bitstream construction is more complex. I_PCM is simpler and gives full control with zero quantization loss.

**Conclusion: I_PCM provides full arbitrary 16-byte control. This is the recommended mode for the exploit macroblocks in rows that feed the top border cache.**

---

## 3. Grooming: Multi-Frame Heap Layout Strategy

### The Core Problem

`top_borders[top_idx]` is allocated once in `ff_h264_frame_start` → `h264_alloc_tables`, which runs before any slices are parsed for that frame. The attacker must arrange the heap **before** this allocation fires. The underflow happens during slice processing, long after the allocation.

### Allocation Pattern in `ff_h264_frame_start`

FFmpeg allocates the following during frame setup (approximate order):

```
1. H264Picture struct          (~400 bytes)
2. AVFrame + data pointers     (~600 bytes)
3. AVBuffer for each plane     (variable, depends on resolution)
4. ref_index arrays            (mb_width * mb_height * 2, per reference)
5. motion_val arrays           (mb_width * mb_height * 2, per reference)
6. top_borders[0][i] for each row i  ((mb_width+1) * 16 bytes)
7. top_borders[1][i] for each row i
8. Various side data, qp_table, etc.
```

The `top_borders` buffers are allocated in a loop over `mb_height` rows. Each buffer is `(mb_width + 1) * 16` bytes (for 8-bit luma; double for high-bit-depth). For a 1920-pixel-wide frame, each buffer is ~31 KB.

### Grooming Strategy: Three-Frame Approach

**Frame N-2 — Stabilize:** Decode a normal I-frame with the same resolution and codec parameters as the exploit frame. This warms up the heap allocator, filling tcache bins and establishing a steady-state layout. All allocations from frame N-2 are freed at the start of frame N-1 if they're not used as references.

**Frame N-1 — Shape the Heap:**

Goal: arrange a small allocation at the position that will be `-88 bytes` from the `top_borders[top_idx]` allocation in frame N.

Strategy: Use reference picture management to control which buffers are allocated and freed.

1. **Allocate sacrificial buffers.** Encode frame N-1 as an I-frame with features that cause FFmpeg to allocate small buffers (e.g., `ref_pic_list_modification`, `pred_weight_table`, or `dec_ref_pic_marking` data). These are allocated during slice header parsing and are typically 64–256 bytes — in the right range for the -88 offset target.

2. **Free sacrificial buffers.** Between frame N-1 and frame N, release the sacrificial buffers by using MMCO commands (e.g., `sliding_window` naturally drops the oldest reference when `num_ref_frames` is exceeded, or `MMCO_RESET` clears all references). The freed buffers go to tcache bins matching their size.

3. **Allocate a specific filler.** After freeing the sacrificial buffers, allocate a filler of the exact size needed to push `top_borders[top_idx]` adjacent to the target. The filler is allocated during frame N's setup, before `top_borders`.

Alternatively, use a more direct approach:

**Approach A — Adjacent Live Struct:**

1. In frame N-1, allocate a buffer B of size S (e.g., 96 bytes for tcache `next` alignment) via a controlled allocation (e.g., `av_mallocz` for `ref_pic_list` data).
2. B remains live (not freed) going into frame N.
3. In frame N, the sequence of allocations during `ff_h264_frame_start` places `top_borders[top_idx]` immediately after B in the heap.
4. The -88 write hits the `next` pointer field of B if B is in tcache, or corrupts a field of B if B is an in-use allocation.

The attacker determines S by analyzing the target FFmpeg binary. The offset from the start of B's user data to -88 from `top_borders[top_idx]` is predictable given the exact allocation sequence.

**Approach B — Tcache Free-Then-Adjacent:**

1. In frame N-1, allocate buffer B (target size) followed by buffer C (larger, e.g., a `top_borders` buffer).
2. Free B. It goes to tcache.
3. In frame N, `av_malloc` for `top_borders[top_idx]` gets C's region (or a new region from the top chunk). B's free chunk sits at -S bytes from wherever `top_borders` is allocated.

This approach requires C to be the same allocation that `top_borders[top_idx]` replaces, which happens naturally: frame N-1's `top_borders` buffers are freed and re-allocated for frame N. If frame N-1 and frame N have the same resolution, the `top_borders` buffers are the same size, and `av_malloc` returns the same chunks (LIFO tcache).

The sequence:
1. Frame N-1: `av_malloc(S)` → B at address A. `av_malloc(T)` → `top_borders_N1` at address A+S+16 (with chunk header). B and top_borders_N1 are adjacent.
2. Frame N-1 ends: B is freed → goes to tcache bin for size S. top_borders_N1 is freed → goes to tcache bin for size T.
3. Frame N starts: `av_malloc(T)` for `top_borders_N2` returns top_borders_N1's chunk (LIFO: same bin, same address). B's free chunk is still at address A, adjacent to top_borders_N2.
4. -88 from top_borders_N2 is at address (A+S+16) - 88. If S ≈ 104, then A+16 is at -88, which is B's `next` pointer field.

**This is the most reliable grooming approach because it exploits FFmpeg's natural frame-to-frame allocation pattern — the same buffers are freed and re-allocated in the same order.**

### Handling posix_memalign Alignment

`av_malloc` uses `posix_memalign(ptr, 32, size)`. This introduces up to 16 bytes of alignment padding between the previous chunk's end and the current chunk's start. The padding varies depending on the alignment of the previous allocation's end address.

The attacker accounts for this by:
1. Determining the exact glibc version and alignment behavior of the target.
2. Adjusting the sacrificial buffer size S to compensate for padding, so that the `next` pointer (or target field) lands exactly at -88 bytes from the aligned `top_borders` base.
3. Using frame N-1 to test the layout empirically (via the XCHG read primitive — see Section 4) and adjust S accordingly.

---

## 4. Alternative: XCHG as a Read-Then-Write Primitive

### The Read Side of XCHG

XCHG is a swap: it reads 16 bytes from the underflow address and writes them to the border cache, while simultaneously writing 16 bytes from the border cache to the underflow address. The 16 bytes read from -88 end up in `top_borders[top_idx][0..15]`, which is the top border cache for the current macroblock column.

After the XCHG, these bytes flow into the macroblock decoding pipeline as the "top neighbor" pixels. They are used for intra prediction of the current macroblock and then stored into the decoded frame buffer.

**Leak path:**
```
underflow address (-88)
    → XCHG reads into top_borders cache
    → used for intra prediction of current MB
    → reconstructed pixels stored in output AVFrame
    → written to the decoded frame buffer
    → accessible to the attacker via the output video
```

### Two-Frame Exploitation: Read First, Then Write

**Frame 1 — Information Leak:**

1. Trigger the underflow with `h->current_slice == 0xFFFF`.
2. The XCHG reads 16 bytes from -88 into the border cache. These bytes are whatever was at that address — a tcache `next` pointer, heap metadata, or content of an adjacent allocation.
3. The border cache pixels propagate into the decoded frame output. The attacker extracts them from the decoded video.

For a local attacker (e.g., `ffmpeg -i exploit.h264 output.yuv`), the YUV output directly contains the leaked bytes as pixel values. For a remote scenario, the attacker may not have direct access to the output, but the leak still occurs within the process.

**What the leak reveals:**
- If -88 hits a free chunk's `next` pointer: leaks a heap address (the next chunk in the tcache freelist). This reveals the heap base, defeating heap ASLR.
- If -88 hits an `AVBufferRef.data` pointer: leaks a pointer to pixel buffer data.
- If -88 hits a `malloc_chunk.size` field: leaks chunk size and flags, revealing heap layout information.
- If -88 hits the start of an `AVCodecContext`: leaks function pointers or vtable addresses, potentially revealing the libavcodec load address (defeating library ASLR).

**Frame 2 — Targeted Write:**

Armed with the leaked address, the attacker now knows:
- The heap base address (if a heap pointer was leaked)
- The absolute address of the target struct or metadata

The attacker constructs frame 2 with I_PCM macroblocks that produce the exact 16-byte payload needed:
- A forged `next` pointer for tcache poisoning (must be XOR-masked on glibc ≥ 2.32)
- A forged `fd`/`bk` for unsorted bin attack
- A forged function pointer or buffer pointer in an adjacent struct

**Frame 2 triggers the underflow again** (a new access unit with 65,535 slices), this time writing the attacker-controlled 16 bytes to -88.

### Defeating glibc Safe-Linking (glibc ≥ 2.32)

Starting with glibc 2.32, tcache `next` pointers are stored as:
```
next_obfuscated = next ^ (chunk_addr >> 12)
```

To poison tcache, the attacker must write the XOR-obfuscated pointer: `target_addr ^ (free_chunk_addr >> 12)`.

The read primitive from Frame 1 leaks the `next` pointer of the free chunk at -88. If the free chunk is in tcache, the leaked value is `actual_next ^ (chunk_addr >> 12)`. Since the attacker knows `chunk_addr` (it's the address of the free chunk at -88, relative to the heap base they've leaked), they can compute:
```
actual_next = leaked_value ^ (chunk_addr >> 12)
target_obfuscated = target_addr ^ (chunk_addr >> 12)
```

The attacker then writes `target_obfuscated` in Frame 2. This requires knowing `chunk_addr`, which the attacker can compute from the leaked heap base and the fixed offset of the grooming chunk within the heap.

### Full Exploit Sequence

```
Frame N-2:  Stabilize heap layout (normal I-frame)
Frame N-1:  Allocate + free sacrificial chunk B at target size
            Allocate top_borders_N1 (adjacent to B)
Frame N:    Allocate top_borders_N2 (reuses top_borders_N1's address)
            B's free chunk is at -S from top_borders_N2
            ── Phase 1: 65,535 slices → underflow fires ──
            XCHG reads 16 bytes from B's `next` pointer into border cache
            XCHG writes 16 bytes of border cache (old pixel data) to B's `next`
            Decoded frame output contains leaked `next` pointer
            ── Extract leak, compute target address ──
Frame N+1:  Encode I_PCM macroblocks with crafted pixel values
            ── Phase 2: 65,535 slices → underflow fires again ──
            XCHG writes forged pointer / payload to -88
            B's tcache bin now returns target_addr on next malloc
            Next allocation from B's size class → arbitrary write
            ── Trigger code execution ──
```

### Reliability Assessment

| Factor | Reliability | Mitigation |
|--------|-------------|------------|
| Heap layout predictability | High (deterministic for same build + input) | Groom offline, verify with read primitive |
| ASLR defeat via info leak | High (leaked heap pointer → heap base) | One-shot leak from Frame 1 |
| Value control (I_PCM) | Full (arbitrary 16 bytes) | None needed |
| Safe-linking defeat | Moderate (requires heap base + chunk offset) | Compute from leaked pointer |
| Target field alignment | Build-specific (varies by FFmpeg version, compiler) | Test against target build |
| Multiple-attempt tolerance | Moderate (can retry with different frame parameters) | Use multiple exploit frames |

**Overall: This is a moderately reliable exploit with a two-frame read-then-write approach. The read primitive eliminates the need to guess heap addresses, and I_PCM provides full payload control. The main uncertainty is the exact alignment of the target field at -88, which is build-specific but deterministic for a given target.**