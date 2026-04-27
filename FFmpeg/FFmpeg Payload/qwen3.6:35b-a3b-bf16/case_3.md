# H.264 Slice Init — Payload Delivery and Grooming Constraints

## Prerequisite

The exploit fires when `h->current_slice == 65535` (0xFFFF), causing `(uint16_t)sl->slice_num == 0xFFFF` to collide with the `slice_table` sentinel. XCHG writes 16 bytes at -88/-72/-56 bytes relative to `top_borders` base, sourced from the border cache pixel row.

---

## 1. Delivery: Reaching 65536 Slices in One Access Unit

### Constraint

An H.264 access unit (AU) — essentially one decoded picture — must contain 65536 slice NAL units to reach the wrap boundary. This is extreme: even a 4K frame at 32×32 MB size needs only ~800 MB rows, and a typical 1080p frame at 16×16 MB needs ~8,100 MBs. One slice = one MB means we'd need a wildly unusual picture structure.

### Transport Options Analysis

| Transport | Survives Pipeline? | Notes |
|------|----------------|---|
| **Raw Annex B file** (`.264`) | YES | FFmpeg's `h264` demuxer reads Annex B natively. No container-level validation. `ffplay malicious.264` or `avcodec_decode_video2` directly accepts any number of NAL units. |
| **RTSP/RTP stream** | PARTIAL | RTP packetization splits NAL units across network packets. Many RTSP stacks enforce maximum packet/sequence limits. However, raw RTP over UDP with crafted sequence numbers can bypass some checks. The RTP depacketizer (`ff_rtsp_rtp_handler`) may drop or re-order if sequence gaps are detected. |
| **HLS segment** (`.ts` or `.mp4`) | NO | HLS uses fragmented MP4 (`fMP4`) or MPEG-TS. Both rely on muxers that enforce structural limits. A fragment with 65536 slices would be rejected by `MP4 muxer` during encoding, and the demuxer may silently truncate on read. |
| **WebRTC** | NO | WebRTC uses `RTCEncodedFrame` with SFrame/SHVC constraints. Browsers enforce strict H.264 conformance (VP9 preferred, H.264 is restricted). Max slices per frame is typically bounded by the decoder implementation (Chrome: ~2048). |
| **Matroska (`.mkv`)** | PARTIAL | The MKV demuxer does not enforce slice counts natively, but many players using FFmpeg (vlc, mpv) may have their own limits. FFmpeg's `matroska` demuxer simply passes NAL units to the codec — if the parent process uses `libavformat` + `libavcodec` directly, this works. |
| **MP4 (`.mp4`)** | NO | ISO Base Media File Format requires `SampleEntry` with valid structure. A sample with 65536 embedded NAL units exceeds the `sample_description` parsing limits in `moov` atoms. |

### Most Reliable Path: Raw Annex B File + Direct libavcodec Invocation

The **most reliable mechanism** is a raw Annex B `.264` file fed directly to a process that uses FFmpeg's libavcodec API without an intermediate demuxer:

```bash
# Direct file decode — no demuxer validation
./avconv -i malicious.264 -c:v rawvideo out.yuv

# Or via ffplay
ffplay -vcodec h264 malicious.264
```

The `h264` demuxer in FFmpeg (`libavformat/h264dec.c`) reads NAL units one-by-one until the next start code (`0x000001` or `0x00000001`). It performs **no structural validation** on slice count. Each NAL unit is passed directly to `ff_h264_slice_header_decode` → `h264_slice_init`.

### Practical Construction

To construct 65536 slices in a single AU:

1. **I-frame with minimal slice headers**: Each slice header in H.264 is small (~20-100 bytes without MB data). 65536 slices × ~50 bytes ≈ 3.2 MB payload — large but feasible.

2. **Use IDR frames**: Each slice is an IDR slice (`nal_unit_type = 5`), ensuring every frame is a random-access point. This simplifies heap state management.

3. **Minimal MB data**: Set `first_mb_addr` to create a single-MB-per-slice picture for the first 65535 slices, then a final slice that triggers the underflow.

4. **Annex B start codes**: Prepend each NAL unit with `0x00 0x00 0x01` (3-byte) or `0x00 0x00 0x00 0x01` (4-byte) start code.

5. **Slice count = MB count**: A 256×256 MB frame (4096×4096 pixels, or ~4K resolution) has ~65536 MBs. Each slice handles one MB. This is a valid (if pathological) H.264 bitstream.

### Key Insight

The target must **not** be a browser, HLS player, or MP4-based pipeline. The most exploitable targets are:

1. **Server-side transcoding** (e.g., `ffmpeg` CLI invoked on a server)
2. **Custom media pipeline** using raw `avcodec_decode_video2` / `avcodec_send_packet`
3. **RTSP client** in an embedded device (e.g., surveillance NVR) that directly passes Annex B NAL units to the decoder

---

## 2. Value Control: How Much Can the Attacker Control the 16 Bytes?

### The Border Cache Population Pipeline

```
Bitstream → CABAC/CAVLC decode → Intra/Inter prediction → Inverse transform →
Inverse quantization → Reconstructed pixel values → Stored in top_borders
```

### H.264 Reconstruction Limits

Pixel values after reconstruction are bounded:

- **8-bit video**: each channel value is in [0, 255], with clamping after any overflow
- **10-bit/12-bit video**: values in [0, 1023] or [0, 4095]
- **Chroma**: typically in [16, 240] for 8-bit (YUV range-limited)

The 16 bytes at `top_borders[top_idx][0..15]` are **consecutive luma pixel values** from the top row of the current macroblock column. Each byte is one reconstructed pixel.

### Influence Model

The attacker can influence pixel values **through the bitstream**, but not with arbitrary precision:

**What the attacker CAN control:**

| Control Level | Mechanism | Precision |
|-----------|------|---------|
| **Prediction mode** | Explicitly setting `pred_mode` in slice header | Deterministic |
| **DC coefficient** | Setting the first DCT coefficient (DC) of a 4×4 block | Directly controls average pixel value |
| **AC coefficients** | Setting transform coefficients for residual | Influences pixel variation within the block |
| **Reference frame selection** | Choosing reference frames in inter prediction | Controls the base pixel values from prior frames |
| **Quantization parameter (QP)** | Per-slice QP in slice header | Controls quantization step size; lower QP = more precision |

**What the attacker CANNOT control:**

| Limitation | Reason |
|------|---|
| Exact pixel-to-byte mapping | Depends on prediction direction (vertical, horizontal, DC, plane modes) |
| Cross-MB dependencies | Neighboring MB prediction uses reconstructed values from neighbors |
| Deblocking filter effects | Post-decode filtering smooths pixel values, changing them slightly |
| Chroma subsampling | For 4:2:0, each chroma sample covers 2×2 luma — not 1:1 |

### Practical Pointer Writing

A pointer on x86-64 Linux has the form `0x00007fXXXXXXXXXX` (typically in the range `0x00007f0000000000` to `0x00007fffffffffff`). The top two bytes are zero (`0x00 0x00`), and the remaining 6 bytes vary.

**Can the attacker write a meaningful pointer?**

**Partial pointer: YES.** The attacker can write 16 consecutive luma pixels, which are typically small values (0-255 for 8-bit). A pointer has the form:

```
Byte 0-1:  0x00 0x00  (high bytes, always zero for canonical addresses)
Byte 2-7:  varies    (heap/libc address bytes)
```

The border cache will contain luma pixel values in [0, 255]. Even if the attacker can set every pixel to an arbitrary value in [0, 255], the first two bytes being `0x00 0x00` is a **lucky match** for canonical addresses. The remaining 6 bytes would be pixel values in [0, 255], which means the resulting "pointer" would only cover the range `0x0000000000000000` to `0x0000000000ffffff` — the **first 1 MB of address space**. This is useless for targeting heap or libc addresses.

**However, there are exploitable scenarios:**

1. **Low-address targets**: If any heap allocation lands below 1 MB (unlikely with ASLR, but possible for kernel allocations or early-boot), the pixel values could serve as a pointer.

2. **Partial overwrite (8 bytes)**: If the XCHG write aligns to an 8-byte boundary in the target, the attacker writes 8 bytes of pixel values (each 0-255). This gives `2^64` possible values but only `2^16` unique byte patterns — the write is constrained to bytes that are each in [0, 255].

3. **Corruption, not replacement**: The XCHG **swaps** values. The target's current content is also read and written back. If the target already contains a pointer (or pointer-sized value), the XCHG replaces it with pixel data. This is **destructive** — it overwrites the target value with data that may or may not be a valid pointer for the next XCHG.

4. **Multi-frame refinement**: Over multiple frames, the attacker can:
   - Read the target's current value via the XCHG read side (see Alternative section)
   - Use that information to craft a better value for the next frame
   - Iterate until the corruption achieves the desired effect

### Conclusion on Value Control

**Direct pointer writing: NOT FEASIBLE** with 8-bit luma pixels (max value 255 each). The 16-byte write produces values like `[0xA3, 0x12, 0xFF, 0x00, ...]` which cannot represent a heap address (e.g., `0x7f8b4c2d1000`).

**Metadata corruption: FEASIBLE.** The 16-byte write can:
- Clear the tcache fd pointer (if target bytes happen to be 0x00)
- Set the fd pointer to a low-address value (useful for tcache with controlled heap layout)
- Corrupt the size field of a preceding chunk (if the write straddles the header)
- Flip specific bits in a pointer if the attacker can influence nearby pixel values

The most practical approach is **corruption-based** (clearing, zeroing, or partially corrupting a pointer/size field) rather than **replacement-based** (writing an exact pointer value).

---

## 3. Grooming: Multi-Frame Heap Arrangement

### Challenge

`top_borders` is allocated once per frame during `ff_h264_frame_start`, which runs before slice parsing. The allocation is for a relatively small, fixed-size buffer (~48 bytes per MB row × `mb_height` rows, rounded up for alignment). To groom the heap, the attacker must arrange for a chosen target to be the **immediately preceding chunk** in the heap layout at allocation time.

### FFmpeg's Per-Frame Allocation Pattern

During `ff_h264_frame_start`:

1. `av_malloc(sizeof(H264Context))` — already allocated, not per-frame
2. `av_mallocz(sizeof(H264SliceContext))` × `nb_slice_ctx` — typically 1-8 per frame
3. `av_mallocz_array(sizeof(H264Picture), nb_refs)` — reference picture structures
4. `av_malloc(height * mb_stride * sizeof(uint8_t))` for various per-MB arrays
5. `av_malloc` for `top_borders` — luma top-border cache (small, ~`mb_height * 16` bytes per row)
6. `av_malloc` for `avc_sps` temporary buffers
7. `av_malloc` for reference frame buffers (if DPB needs expansion)

Key: `top_borders` is a **small allocation** (~hundreds of bytes for 1080p). Its preceding chunk is whatever was allocated most recently before it, or a freed chunk that happened to be adjacent.

### Multi-Frame Grooming Strategy

#### Frame N-2: Establish Baseline Allocation Pattern

Send a normal decode request that allocates a known set of objects. This establishes the heap state.

#### Frame N-1: Create and Free the Target Chunk

**Goal**: Allocate a chunk of a specific size, then free it, so it becomes a free-list entry at a known position relative to where `top_borders` will be allocated.

**Steps**:

1. **Allocate a controlled chunk**: Use the bitstream to trigger allocation of an object whose lifetime extends beyond `ff_h264_frame_start`. For example:
   - An `AVFrame` buffer descriptor (`av_frame_alloc` + `av_frame_get_buffer`) — this allocates a `AVBufferRef` with associated data
   - A reference frame buffer (`av_malloc(width * height * 3 / 2)` for YUV420) — large, but allocates before `top_borders`

2. **Size the chunk**: The tcache in glibc 2.26+ has buckets for sizes 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, etc. The `top_borders` allocation is typically ~0x200-0x1000 bytes. The preceding chunk should be **freed** and its tcache entry in a bucket that doesn't interfere with `top_borders`'s own size class.

3. **Free the chunk**: Complete the decode (or abort it) to free the chunk. The freed chunk's data region becomes a tcache entry.

#### Frame N: The Trigger Frame

**Goal**: Ensure `top_borders` is allocated immediately after the freed chunk.

**Steps**:

1. **Send the trigger bitstream**: 65536 slices in one AU, with slice 65536 triggering the underflow.

2. **Rely on allocation ordering**: If FFmpeg's allocation pattern is deterministic across frames (same frame size, same codec config), the `top_borders` allocation will happen at the same heap position relative to the freed chunk from the previous frame.

3. **Iterate**: If the first attempt doesn't position the target correctly, send multiple frames with varying parameters to shift the heap layout.

### Alternative Grooming: Multi-Allocation Squeeze

Instead of relying on a single freed chunk, the attacker can **squeeze** the target between two known allocations:

1. Allocate a large object `A` (e.g., a reference frame buffer ~2 MB for 1080p YUV420)
2. Allocate `top_borders` — it should land right after `A` if no other allocation happens in between
3. Free `A` — now `A`'s data region is at -88 bytes relative to `top_borders`
4. The freed chunk `A` is in the unsorted bin (too large for tcache)

**Problem**: `A` is large (MBs), so the -88 byte offset only touches a tiny fraction of it. The content at -88 bytes is `A`'s data, which is pixel data from a prior frame — not a useful free-list pointer.

**Better approach**: Use a **small freed chunk** that lands in tcache:

1. Allocate a small chunk `C` (~0x60-0x100 bytes, same size as `top_borders`)
2. Immediately free `C` — it enters the tcache
3. Allocate `top_borders` — it lands right after `C` in the heap
4. Now `C`'s tcache fd pointer sits at -88 bytes

### Grooming Target Selection

| Target | Size Class | Allocation Trigger | Preceding Position |
|--------|-----|----------------|------|
| `AVBufferRef` (frame descriptor) | ~0x60 | `av_frame_get_buffer` | Possible via frame reuse |
| `H264Picture` reference entry | ~0x100 | DPB management | Possible via reference frame manipulation |
| `uint8_t` slice-row array | ~0x200 | `ff_h264_frame_start` | Likely, as it's allocated nearby |
| Temporary CABAC context | ~0x40 | Slice header decode | Possible during slice parsing |

### Grooming Success Rate

| Factor | Impact |
|--------|---|
| Consistent frame size | High — deterministic allocation pattern |
| Consistent codec configuration | High — same allocations every frame |
| No external allocations (e.g., logging, debug) | High — reduces heap fragmentation |
| Process longevity | Low — long-running processes have fragmented heaps |
| Single-threaded decode | High — avoids tcache per-thread contention |

**Estimated success rate**: In a controlled server environment with per-request FFmpeg initialization, the grooming window is large enough for success within 10-100 attempts. In a long-running process, 1000+ attempts may be needed.

---

## 4. Alternative: Heap Info-Leak via XCHG Read Side

### The XCHG Read Primitive

XCHG reads 16 bytes from the underflow address and writes them to the border cache. The border cache content then influences:
- **Future XCHG writes** (the cache content becomes the written value)
- **Decoding output** (pixel values are written to the output frame)

### Info-Leak Strategy

#### Step 1: Groom to Place a Heap Pointer at -88 Bytes

Arrange for the preceding chunk at -88 bytes to contain a heap pointer (e.g., a tcache fd pointer, or a pointer field in a codec object).

#### Step 2: Trigger XCHG — Read the Pointer

The XCHG reads the 16 bytes from -88 bytes and writes them to the border cache. This reads:
- tcache fd pointer → reveals a heap address (part of the heap layout)
- libc pointer in codec object → reveals a libc address

#### Step 3: Exfiltrate the Read Value

The read value is now in the border cache and influences:
- **Decoded pixel output**: The pixel values are written to the output frame buffer. If the attacker receives the decoded output (e.g., in a transcoding service), the heap address is leaked as pixel data.
- **Side channel via error messages**: If the corrupted pixel values cause a subsequent decoding error, the error message or crash dump may reveal the memory contents.
- **Visual artifact analysis**: For a local player, the attacker watches the decoded video for visual artifacts that encode the leaked bytes.

#### Step 4: Use the Leak to Refine the Exploit

With the leaked address:
1. **Compute heap base**: Subtract known offset from heap ASLR base
2. **Compute libc base**: If a libc pointer was leaked, compute offsets to `system()`, `__free_hook`, etc.
3. **Identify new targets**: Now the attacker knows the exact layout and can groom for a more precise write target
4. **Iterate the XCHG**: Use the leaked information to craft a better 16-byte value for the next XCHG write

### Multi-Stage Exploit

```
Round 1: Groom → Trigger XCHG → Read pointer → Leak heap/libc address
Round 2: Groom for precise write target → Craft value using leaked layout → Trigger XCHG → Write corrupted pointer
Round 3: Trigger the corrupted pointer → Execute controlled code
```

### Advantages of Info-Leak First

| Advantage | Explanation |
|------|------|
| Bypasses ASLR | Leaks give actual addresses, eliminating the need to guess |
| Reduces grooming precision | With known layout, the attacker can target the exact chunk at -88 bytes |
| Validates the primitive | Confirms the underflow is firing and the read value is useful |
| Iterative refinement | Each round improves the chances of the next |

### Disadvantages

| Disadvantage | Explanation |
|------|------|
| Requires output access | The attacker must receive decoded frames to read leaked pixel values |
| Timing | Each round requires a full frame decode, increasing total exploit time |
| Pixel quantization | The leaked bytes may be partially corrupted by quantization |
| Detection risk | Multiple failed/exploit attempts increase crash rate, raising alert visibility |

---

## Summary

| Constraint | Feasibility | Best Approach |
|------------|-----|------|
| **Delivery (65536 slices)** | Medium | Raw Annex B file + direct libavcodec invocation; avoid MP4/MKV/HLS |
| **Value control (16 bytes)** | Low | Cannot write arbitrary pointers; corruption-based approach (clearing, zeroing) is more viable than replacement |
| **Grooming** | Medium-Hard | Multi-frame strategy: allocate+free target chunk, then trigger on next frame; works best in per-request server environment |
| **Info-leak alternative** | Medium | Use XCHG read side to leak heap/libc addresses from border cache, then refine exploit iteratively |

### Overall Exploitation Path (Most Likely to Succeed)

1. **Target**: Cloud transcoding service accepting raw H.264 Annex B input
2. **Round 1**: Send 65536-slice bitstream → trigger underflow → XCHG reads heap pointer → leaked as pixel value in decoded output
3. **Round 2**: Use leaked address to compute heap/libc layout → groom for tcache fd target at -88 bytes → craft 16-byte value to zero/clear the fd pointer (or write low-address value) → trigger underflow → tcache poisoned
4. **Round 3**: Trigger allocation that returns poisoned address → write shellcode → overwrite function pointer → RCE

This is a **multi-round, probabilistic exploit** that works best in a controlled, server-side context with repeated decode attempts and output inspection.
