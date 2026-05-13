# Payload Constraints Analysis: h264_slice_init Exploitation

## 1. Delivery Mechanism for 65536 Slice NAL Units

The most reliable transport-level mechanism is **raw Annex B bytestream** delivered via:

- **Direct file read**: A `.h264` file containing Annex B NAL units, fed to `ffmpeg` or a media player that uses FFmpeg's H.264 decoder.
- **RTSP/RTP stream**: Real-time streaming protocols that transmit Annex B NAL units directly over UDP/TCP, commonly used in IP cameras and video surveillance.
- **HTTP progressive download**: Serving an Annex B file over HTTP with `Content-Type: video/H264`.

**Why Annex B succeeds:**
- Annex B (start-code prefixed NAL units) is the native format for FFmpeg's H.264 parser (`h264_parse`). It imposes no structural limit on slices per picture.
- Container formats (MP4, MKV) use length‑prefixed NAL units and enforce stricter structural checks; muxers often reject pictures with >8192 slices as malformed.
- RTSP/RTP with H.264 payload type (RFC 6184) transmits Annex B‑like NAL units, making it viable for live exploitation.

**Real‑world parsing pipelines:**
- **HLS**: Uses MPEG‑TS containers, which may impose similar limits as MP4.
- **WebRTC**: Uses RTP with H.264, but the WebRTC stack may perform additional sanity checks.
- **DASH**: Typically uses MP4 fragments, subject to container limits.

**Conclusion:** Raw Annex B (file or RTSP) is the most reliable because it reaches the decoder with minimal intervening validation.

## 2. Value Control Over the 16‑Byte Underflow Write

H.264 reconstructs pixel values through a pipeline: transform coefficients → quantization → inverse transform → prediction. The attacker controls the transform coefficients, but quantization introduces loss and limits precision.

**Influence breakdown:**
- **Pixel range**: Luma samples are 8‑bit (0‑255). The attacker can set each byte to any value in that range, but not arbitrary 64‑bit values in one sample.
- **Prediction**: If the macroblock uses intra prediction, pixel values are derived from neighbouring blocks, reducing direct control. However, the attacker can choose **intra 16×16 DC mode** where the entire 16×16 block is filled with a single DC value (transmitted as a coefficient). This allows setting all 16 top‑border pixels to the same 8‑bit value.
- **Multiple macroblocks**: To write a full 64‑bit pointer, the attacker would need eight consecutive macroblock columns, each contributing one byte of the pointer. This is possible if the underflow occurs at `mb_x == 0` of a new row; the preceding row’s top‑border cache would contain pixels from eight macroblocks (columns 0‑7). The attacker can encode the pointer across those eight columns.

**Practical control:**
- **Full pointer writing feasible**: With intra DC prediction and careful coefficient selection, the attacker can place specific byte values in the border cache. However, quantization may alter the exact value slightly (e.g., a coefficient of 1000 may reconstruct to 998). This error is small enough that the written pointer will still point into a nearby memory region (off by a few bytes), which may be acceptable for heap‑metadata corruption.
- **Partial corruption possible**: If precise pointer placement fails, the attacker can still overwrite chunk metadata with non‑zero bytes, potentially breaking heap invariants (e.g., clearing the `PREV_INUSE` bit or corrupting `size`).

**Conclusion:** The attacker has **substantial but not perfect** control; writing a meaningful pointer is feasible with intra DC prediction across multiple macroblocks.

## 3. Multi‑Frame Heap Grooming Strategy

Because `top_borders` is allocated once per frame in `ff_h264_frame_start`, grooming must occur **before** that allocation. A multi‑frame approach:

**Phase 1: Heap shaping with dummy frames**
1. Send a series of “grooming frames” that allocate and free specific buffers to create holes in the heap.
2. Use H.264 parameters that trigger allocations of known sizes (e.g., reference frames, `AVFrame` buffers, motion‑vector tables).
3. Free some of these buffers just before the target frame, leaving free chunks of desired size in specific heap regions.

**Phase 2: Placing the target**
4. In the frame preceding the attack frame, allocate a victim object (e.g., a tcache chunk of size 0x60, or an `AVFrame` with a vtable pointer) that will be freed just before `top_borders` allocation.
5. Time the free such that the freed chunk sits immediately before the memory region where `top_borders` will be allocated.

**Phase 3: Aligning `top_borders`**
6. `top_borders` is allocated via `posix_memalign`. The alignment requirement (likely 16 or 32 bytes) determines the offset between the chunk start and the returned pointer. The attacker can influence this by choosing a frame size that causes `posix_memalign` to request a particular alignment.
7. By controlling the size of preceding allocations, the attacker can ensure that the freed chunk’s metadata lies at a predictable offset from the aligned `top_borders` pointer, making the -88 bytes land exactly on the target field (e.g., `fd` of a tcache chunk).

**Phase 4: Trigger underflow**
8. In the same frame where `top_borders` is allocated, include 65536 slices to trigger the sentinel collision and underflow write.

**Challenge:** The exact heap layout depends on many factors (ASLR, previous decoder state). However, the attacker can repeat the grooming sequence across many frames to increase probability, or use the read side of XCHG to probe the layout first (see alternative below).

## 4. Alternative: Underflow as Info‑Leak Primitive

The XCHG primitive **reads 16 bytes** from the underflow address before writing. This provides a **heap‑info‑leak** capability:

**Step 1: Leak chunk metadata**
- Trigger the underflow without careful grooming.
- The read 16 bytes will contain whatever lies at -88 before `top_borders` (likely chunk header or adjacent object data).
- Transmit the leaked bytes back to the attacker via **side channel**:
  - Encode them in the **output pixel data** of the decoded video (if the decoder is rendering).
  - Use a **timing side channel** (e.g., influence deblocking filter processing time based on leaked values).
  - In a client‑server scenario (RTSP), the attacker can receive the decoded video stream.

**Step 2: Calculate heap layout**
- From the leaked chunk header, compute the base address of the chunk, the heap arena, and possibly the `main_arena` address.
- Use this to defeat ASLR and determine where to place a fake chunk or which function pointer to overwrite.

**Step 3: Groom precisely**
- With heap addresses known, the attacker can send a second grooming phase that places a target at a calculated offset.
- Trigger the underflow again, now writing a controlled pointer to the known address.

**Advantage:** This two‑stage approach relaxes the need for exact grooming upfront. The attacker first probes the layout, then crafts the final exploit.

**Feasibility:** The leak is reliable because the read always occurs. The challenge is exfiltrating the leaked data. If the decoder is part of a video player that displays output, the attacker can encode the leaked bytes into visible pixel values of subsequent frames (steganography).

## Overall Exploitability Summary

The constraints are significant but not fatal:

- **Delivery** via raw Annex B is straightforward.
- **Value control** allows pointer‑like writes with some error; partial corruption may still be exploitable.
- **Grooming** requires multi‑frame orchestration but is feasible with heap‑shaping techniques.
- **Alternative info‑leak path** provides a way to overcome grooming uncertainties.

Thus, a real‑world weaponisation is **challenging but possible**, especially in scenarios where the attacker can interact repeatedly with the decoder (e.g., video‑on‑demand server, RTSP stream).