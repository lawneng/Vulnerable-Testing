# H.264 Payload Constraint Analysis

## 1. Delivery: Transporting 65536 Slice NAL Units

### Assessment of transport mechanisms

| Transport | Survives? | Reason |
|-----------|-----------|--------|
| **Raw Annex B bytestream** (file or pipe) | **Yes** | No container structure to validate. NAL units are delimited by `0x000001` / `0x00000001` start codes. The parser simply reads NAL units sequentially. No slice-count limit exists in Annex B. |
| **RTSP/RTP** | **Likely yes** | Each RTP packet carries one NAL unit (or FU-A fragment). The depacketizer reassembles NAL units but does not count them. An attacker can stream 65536 NAL units across as many RTP packets as needed. Some RTSP servers enforce session timeouts but not slice-count limits. |
| **HLS segment** | **Likely yes** | HLS segments are raw MPEG-TS or fMP4. MPEG-TS wraps H.264 in PES packets with no slice-count constraint. The TS demuxer passes NAL units through to the decoder without filtering on slice count. |
| **MP4/MKV container** | **No** | Both muxers store slices as multiple sample entries within a single sample. MP4's `stsz`/`stsc` boxes and MKV's Block structure impose practical limits. Most muxers reject or truncate pictures with >8192 slices. ffmpeg's own muxer caps at `FFMAX_SLICES` (typically 16–32). |
| **WebRTC** | **Unlikely** | WebRTC uses SRTP with constrained bandwidth. 65536 slice NAL units would produce an enormous frame size (~100+ MB for minimal content per slice). Congestion control and jitter buffers would drop or reorder packets, making complete delivery improbable within the frame's decode deadline. |

### Most reliable delivery mechanism

**Raw Annex B bytestream delivered as a file** is the most reliable. Reasons:

1. **No container validation.** The Annex B parser (`h264_parser.c`) reads NAL units by scanning for start codes. It has no slice-count field and no maximum. It simply yields each NAL unit to the decoder.

2. **Direct file-reading path.** FFmpeg's `avcodec_decode_video2` / `avcodec_send_packet` path processes packets sequentially. When reading a raw `.264` or `.h264` file, the demuxer (`rawvideo` or `h264` demuxer) creates one packet per access unit, but the parser splits NAL units without enforcing count limits.

3. **Works with all FFmpeg frontends.** `ffplay`, `ffmpeg -i input.264`, and any application using `libavformat` with the H.264 raw demuxer will accept the stream.

4. **Minimal overhead.** Each slice NAL unit needs only a 4-byte start code (`0x00000001`), a 1-byte NAL header, and a minimal slice header (roughly 5–15 bytes for I-slice with `first_mb_in_slice` and quantization parameters). A 65536-slice payload is approximately 65536 × ~20 bytes ≈ 1.3 MB — trivially deliverable.

**RTSP stream** is the second-best option for network delivery. The attacker streams Annex B NAL units over RTP, and the receiver reassembles them without slice-count validation. This works for targets that process network streams (IP cameras, streaming servers).

**Practical concern:** Some FFmpeg builds have a `MAX_SLICES` compile-time constant (default 16 in some configs, 256 in others). If `h->nb_slice_ctx` is allocated based on `MAX_SLICES`, the 65535th slice would trigger an allocation failure before reaching the underflow. The attacker must target a build where `MAX_SLICES >= 65536` or where the slice context array is dynamically resized. This is a compile-time constraint, not a transport constraint.

---

## 2. Value Control: Attacker Influence Over the 16-byte XCHG Payload

### How border cache pixels are reconstructed

The 16 bytes written at the underflow address come from `h->top_borders[top_idx][0..15]` — the reconstructed luma pixel values from the row above the current macroblock. These bytes are **not** raw bitstream data. They are the output of the H.264 reconstruction pipeline:

```
prediction (intra or inter) → residual transform (IDCT/IFFT) → addition → clip to [0,255] → top_borders
```

### Source of control

**Intra prediction (I-slice, I-MB):** The attacker chooses the intra prediction mode (vertical, horizontal, DC, planar, etc.). For vertical prediction, the top border is copied from the reference pixels above, which themselves were reconstructed from earlier macroblocks. For DC/planar modes, the reconstructed value is a deterministic function of reference pixels. The attacker controls the transform coefficients in the bitstream, which directly set the residual added to the prediction.

**Inter prediction (P/B-slice, P/B-MB):** The reconstructed pixel is `prediction + residual`, where prediction comes from a reference frame and residual comes from transform coefficients. The attacker controls both the motion vector (choosing which reference pixels to copy) and the transform coefficients.

### Degree of control

**For I-MB with explicit transform coefficients (CAVLC or CABAC):**

The H.264 transform pipeline for luma is:
1. Decode quantized coefficients from the bitstream (attacker controls these directly)
2. Dequantize: `level × (QP × 6 + 52) / 16` (or equivalent, depending on QP and table)
3. Inverse transform: 4×4 Hadamard (DC) and 4×4 IDCT (AC)
4. Add prediction and clip to [0, 255]

The mapping from coded coefficients to reconstructed pixels is **deterministic and invertible for a known QP and prediction mode**. Given a desired output pixel value `p`, the attacker computes the required transform coefficients `c` by reversing the pipeline:

```
residual = p - prediction
transform coefficients = forward_transform(residual)
quantized coefficients = quantize(transform coefficients, QP)
```

This means the attacker has **full byte-level control** (0x00–0xFF) over each reconstructed pixel, subject to:

- **QP constraints:** At very high QP (coarse quantization), the quantization step may make some pixel values unreachable because the dequantized residual cannot produce fine-grained values. The attacker mitigates this by using **QP = 0** (finest quantization, step size 1), which gives essentially lossless reconstruction and full control over all 256 pixel values.

- **Prediction mode constraints:** Some intra prediction modes produce deterministic reference values that limit the range of reconstructed pixels for a given residual. The attacker uses **PCM macroblocks** (H.264 `mb_type = I_PCM`) as an escape: PCM MBs bypass the transform pipeline entirely and store pixel values directly in the bitstream, giving **perfect byte-level control** with zero quantization error.

- **CABAC/CAVLC encoding:** The attacker must encode the chosen coefficients into a valid CABAC or CAVLC bitstream. This is a coding constraint, not a value constraint — every valid coefficient sequence has a valid encoding. The bitstream size increases for large coefficient magnitudes, but all values 0–255 are representable.

### Verdict on value control

**The attacker has full byte-level control (0x00–0xFF per byte) over all 16 bytes of the XCHG payload.** This is achieved by:

1. Using **PCM macroblocks** for the row above the underflow trigger, which embed pixel values verbatim with no transform or quantization.
2. Alternatively, using **I-MB with QP=0** and computed transform coefficients to produce exact desired pixel values through the reconstruction pipeline.

With PCM MBs, the 16 bytes written at the underflow offset are **exactly the 16 bytes the attacker places in the bitstream**. This is sufficient to write:
- A full 8-byte pointer (little-endian) for tcache poisoning, with the remaining 8 bytes set to a valid `key` value or arbitrary padding.
- A full 8-byte function pointer plus 8 bytes of arguments for overwriting callback descriptors.
- Any other arbitrary 16-byte value needed for the exploit.

**Constraint B is not a real constraint** — the attacker has essentially perfect control over the written value through PCM macroblocks.

---

## 3. Grooming: Multi-Frame Heap Layout Strategy

### The fundamental timing constraint

`top_borders` is allocated in `ff_h264_frame_start` → `alloc_picture` → `alloc_table`, which runs **once per frame, before any slices are parsed**. The attacker must groom the heap *before* this allocation, using allocations from **previous frames**. The underflow then fires during decoding of frame N, but the grooming must be complete by the time `top_borders` for frame N is allocated.

### Multi-frame grooming strategy

#### Frame 1–K: Heap priming (establish baseline)

1. **Choose SPS parameters** that set the picture dimensions and thus the `top_borders` allocation size. The attacker fixes these for the entire exploit stream — same SPS for all frames.

2. **Decode K normal frames** to populate the heap with the expected decoder allocations (reference frame buffers, slice contexts, reference lists, CABAC contexts). This stabilizes the heap layout by filling tcache bins and small-object caches with the expected mix of allocations.

3. **Observe** (if local) or **estimate** (if remote) the heap state after K frames. After several frames, FFmpeg's allocator reaches a steady state where freed objects from the previous frame are reallocated for the current frame, creating a cyclical allocation pattern.

#### Frame K+1: Create the hole (free the target chunk)

1. The attacker arranges for a specific object — say, an `AVBufferRef` of size class S — to be allocated adjacent to where `top_borders` will be.

2. **Strategy:** Allocate many objects of size class S during frame K (by having many reference pictures in the DPB). Then, during frame K+1, reduce the reference picture count, causing `unref_picture` to free specific `AVBufferRef` objects of size class S.

3. The freed `AVBufferRef` goes into the tcache bin for size class S (if S ≤ 1032 bytes on 64-bit glibc, which it almost certainly is — `AVBufferRef` is ~48 bytes).

4. **Key insight:** The attacker doesn't need to free the exact adjacent object. They need to ensure that when `top_borders` is allocated, the tcache bin for the size class that covers the -88/-72/-56 offset region contains a free chunk at that location. This is equivalent to saying: the object that was *freed* at that offset must be in the same tcache bin, and `top_borders` must be allocated adjacent to it.

#### Frame K+2: Allocate top_borders adjacent to the hole

1. `ff_h264_frame_start` runs for frame K+2. It calls `alloc_picture`, which calls `av_malloc` for `top_borders`.

2. The attacker controls the *size* of the `top_borders` allocation by setting the picture width in the SPS. A wider picture means a larger `top_borders` allocation, which means a different size class and thus a different tcache bin.

3. By choosing the picture width carefully, the attacker ensures that `top_borders` is allocated from the same heap region as the freed `AVBufferRef` from frame K+1, and specifically that `top_borders` is placed immediately after the freed chunk in memory.

4. **Coalescing avoidance:** If the freed chunk and `top_borders` are in different size classes, they will be in different tcache bins and will not coalesce. This is actually desirable — the attacker wants a freed tcache chunk at a known offset from `top_borders`, not a merged free region.

#### Frame K+2, slice 65535+: Trigger the underflow

1. After `top_borders` is allocated and the first 65534 slices are decoded, slice 65535 triggers the `slice_num == 0xFFFF` collision.

2. The XCHG fires at `top_borders[top_idx][-1]`, hitting the freed tcache chunk at -72 bytes.

3. The 16-byte write overwrites the tcache `next` pointer with an attacker-controlled address.

#### Why this works: deterministic tcache ordering

glibc's tcache is a LIFO (last-in, first-out) singly-linked list. The most recently freed chunk of a given size class is the next one allocated. This means:

- If the attacker frees chunk A, then chunk B (same size class), tcache order is B → A.
- The next `malloc` of that size class returns B, then A.

By controlling the order of frees in frame K+1, the attacker controls which freed chunk is at the head of the tcache list, and thus which chunk `top_borders` is allocated next to (or whether `top_borders` itself is carved from a specific free region).

### Specific grooming recipe

```
Frame 1-5:   Normal frames, building up reference picture list.
              DPB fills with 8-16 reference pictures.
              Heap stabilizes.

Frame 6:     Reduce DPB to 4 references by not signaling long-term refs.
              Frees ~12 AVBufferRef objects of ~48 bytes each.
              These go into tcache bin for 48-byte class.

Frame 7:     SPS change (new sequence) to trigger reallocation of top_borders.
              alloc_picture() calls av_malloc(top_borders_size).
              top_borders is allocated from the heap region previously occupied
              by one of the freed reference frame buffers.
              The freed tcache chunk at -72 bytes from top_borders is the
              AVBufferRef that was freed last (LIFO ordering).

Frame 7:     Decode 65535 slices. At slice 65535, underflow fires.
              XCHG overwrites the freed AVBufferRef's memory at -72 bytes,
              which is now a free tcache chunk. The write hits the
              tcache `next` pointer.

Frame 8:     Normal decode operation calls malloc(48), which returns
              the attacker-controlled address from the poisoned tcache.
              Decoder writes reference data there, then frees it,
              calling the corrupted pointer → code execution.
```

### Grooming reliability

- **Locally deterministic:** Given a fixed binary and fixed SPS/PPS, the allocation sequence is deterministic. The attacker can test locally to find exact offsets.
- **Remotely probabilistic with narrowing:** The XCHG read primitive (see section 4) leaks heap addresses, allowing the attacker to adapt. Multiple attempts across frames increase success probability.
- **SPS-triggered reallocation** is the key mechanism. The H.264 bitstream allows SPS changes between frames, causing the decoder to reallocate internal buffers including `top_borders`. This gives the attacker a fresh grooming opportunity on each SPS change.

---

## 4. Alternative: Leak-First Strategy Using XCHG Read

If precise grooming is infeasible (e.g., due to unknown binary layout, hardened allocator, or inability to control allocation order), the attacker can use the XCHG primitive as a **read-first** exploit, leveraging the swap semantics to leak heap metadata before corrupting it.

### The read primitive

XCHG swaps 16 bytes at the target address with 16 bytes from the border cache. The swapped-in data (from the target) is written into `top_borders`, which is later used in decoding and ultimately written to the output frame buffer. If the attacker can extract the decoded frame, they recover the 16 bytes read from the target address.

### Two-phase strategy

#### Phase 1: Information leak (frames K through K+65535)

1. **Do not groom.** Let the heap be in its natural state. Decode frames until `current_slice == 65535` triggers the underflow.

2. **The XCHG fires at -88/-72/-56.** Whatever data is at those offsets (free chunk `fd`/`bk` pointers, heap metadata, struct fields) is swapped into the border cache and decoded into the output frame.

3. **Extract the leaked data.** The leaked 16 bytes appear in the reconstructed frame at known pixel coordinates (the position of the underflowing macroblock). The attacker encodes the output frame to a lossless format (PNG) or reads raw pixel data to recover the exact byte values.

4. **What the leak reveals:**
   - If the target offset hits a free tcache chunk: the `next` pointer (heap address) and `key` (deterministic value, confirms tcache membership).
   - If the target offset hits a free unsorted/smallbin chunk: the `fd` and `bk` pointers (heap and potentially libc addresses — unsorted bin `fd`/`bk` point into the `main_arena` in libc).
   - If the target offset hits an `AVBufferRef`: the `buffer` and `data` pointers (heap addresses).

5. **From the leaked address, compute target addresses.** A leaked libc address (from unsorted bin `fd`/`bk`) gives the libc base, enabling computation of `__free_hook` (pre-2.34) or one-gadget addresses. A leaked heap address gives the heap base, enabling computation of the `top_borders` address and thus the exact offset to the tcache `next` field.

#### Phase 2: Targeted write (frame K+1 through K+1+65535)

1. **Now the attacker knows the heap layout.** Using the leaked addresses, compute the exact value to write: a pointer to `__free_hook` (for tcache poisoning) or a one-gadget address (for function pointer overwrite).

2. **Encode the payload into pixel values.** Using PCM macroblocks (as established in section 2), set the 16 border cache bytes to the computed payload.

3. **Trigger the underflow again** on the next frame with `current_slice == 65535`.

4. **The XCHG writes the attacker's payload** at the target offset, now with full knowledge of what to corrupt and where.

### Why this works across frames

- `top_borders` is reallocated each frame (or each time SPS parameters change). The attacker can trigger multiple underflows across multiple frames, each with different payload values.
- The first underflow is a **pure read** (the written pixel values are irrelevant — only the swapped-in data matters). The second underflow is a **targeted write** (using the leaked addresses to craft the payload).
- There is no limit on the number of underflow attempts — the attacker can trigger one per frame, limited only by the 65535-slice-per-frame requirement.

### Reliability of the leak-first approach

| Aspect | Assessment |
|--------|------------|
| **Leak reliability** | High. The XCHG read swaps 16 bytes unconditionally. The data appears in the decoded frame at known pixel positions. No crash occurs from the read phase (the write side writes pixel data into heap memory, which may cause corruption, but the process survives long enough to produce the output frame). |
| **Write reliability after leak** | High. With leaked addresses, the attacker knows exactly which tcache bin to poison and what address to write. The second underflow writes a precise, computed payload. |
| **ASLR bypass** | Complete. The leak provides either a heap address (for tcache poisoning) or a libc address (for GOT/function pointer overwrite). One leaked address is sufficient. |
| **Safe-linking bypass (glibc ≥2.32)** | Complete. Safe-linking XORs the tcache `next` pointer with `((chunk_addr >> 12) ^ 0)`. The leak phase provides the chunk address (it's at a known offset from `top_borders`), so the attacker computes the XOR mask and writes the correctly mangled pointer. |
| **Overall exploit reliability** | **High** — the leak-then-write strategy converts a probabilistic exploit into a deterministic one. The only uncertainty is whether the process crashes during the first underflow's write phase (the 16 bytes written into the heap may corrupt something). This risk is mitigated by choosing a target offset that hits free memory (tcache chunks) rather than live data. |

### Degraded mode: crash during leak phase

If the first underflow's write corrupts live heap data and causes a crash before the frame is output, the attacker can:

1. **Use a different offset.** The three underflow points (-88, -72, -56) target different data. Try each until one hits free/unused memory.
2. **Use a different allocation size.** Changing the SPS picture width changes the `top_borders` allocation size, changing which tcache bin it falls into and thus which adjacent objects appear at the target offsets.
3. **Accept the crash and retry.** The process restarts with a new ASLR base, and the attacker tries again. With ~3 target offsets and multiple allocation sizes, the probability of a clean leak within a few attempts is high.

**The leak-first strategy is the preferred approach for real-world exploitation.** It requires no advance knowledge of the target binary's heap layout and provides complete ASLR bypass. The cost is delivering two sets of 65536 slices (one for leak, one for write), which doubles the payload size to ~2.6 MB — still trivially deliverable as a raw Annex B file.