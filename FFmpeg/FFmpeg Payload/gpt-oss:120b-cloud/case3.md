# FFmpeg `h264_slice_init` Payload Constraint Assessment

## 1. Delivery – reliable transport for 65 536 slice NAL units

| Transport | How it works | Compatibility with real‑world parsers | Likelihood of being dropped |
|------------|---------------|--------------------------------------|----------------------------|
| **Raw Annex B bytestream** (`.h264` file) | Concatenates NAL units as start‑code prefixes (`0x000001` or `0x00000001`). No container limits. | FFmpeg’s demuxer (`h264`) parses the stream directly, feeding each NAL to the decoder. | **Never dropped** – the demuxer has no slice‑count check, only validates start codes and NAL types. |
| **RTSP/RTP** (H.264 over RTP) | Each RTP packet carries one or more NAL units (including fragmented NALs). The RTP payload parser reassembles the byte stream before handing to the decoder. | Most RTP stacks forward the payload unchanged; slice limit is not enforced by the protocol. | **Very high** – as long as packet size limits are obeyed (max 1400 B typical), the large number of slices can be split across many packets. |
| **HLS (MPEG‑TS segments)** | Segments contain H.264 elementary streams inside MPEG‑TS. The TS muxer does not enforce slice count per picture. | When the encoder writes a TS segment, the TS layer only cares about packet boundaries, not slice numbers. |
| **WebRTC (RTP over DTLS/SCTP)** | Same as RTP, wrapped in SRTP. | Similar to RTSP – no slice limit. |

**Conclusion:** The most reliable mechanism is a **raw Annex B file** (or an equivalent RTP‑based stream). It bypasses any container‑level slice‑count sanity checks that MP4/MKV containers impose. An attacker can ship a `.h264` file or a live RTP stream containing 65 536 slice NAL units without being silently truncated.

---
## 2. Value control – how much of the 16‑byte write can be dictated

The XCHG primitive swaps the 16‑byte value stored in `top_borders[top_idx][0..15]` with the memory at the underflow address. `top_borders` holds the **top‑row pixel values** for the current macroblock column. Those pixels are derived from:
1. **Prediction** (intra‑mode intra‑prediction or inter‑prediction from the previous frame).
2. **Residual transform coefficients** which are de‑quantised and inverse‑DCT’d.
3. **Clipping** to the valid luma range (0‑255).

Because the attacker fully controls the macroblock data preceding the underflow macroblock (the macroblock row above the first column of slice 65536), they can set the **exact 8‑bit luma values** for those 16 bytes, subject to:
- **Quantization step size** – higher QP reduces precision, but the attacker can still choose any value in the 0‑255 range by adjusting transform coefficients appropriately (using a zero‑coefficient block yields the predictor value; non‑zero coefficients add/subtract limited amounts). In practice, with QP ≤ 30 the attacker can hit any byte value with a few coefficient tweaks.
- **Prediction mode** – intra‑prediction can copy from neighbouring pixels, which the attacker also controls earlier in the picture, giving another degree of freedom.

**Result:** The attacker can **fully control all 16 bytes** of the row, i.e., they can write an arbitrary 128‑bit value. This is sufficient to encode a **pointer (8 bytes) plus a filler or another pointer**. If the target is a 16‑byte chunk‑header (tcache `next` pointer + padding) the attacker can set the exact `next` address they need.

---
## 3. Grooming – multi‑frame strategy to place a target structure at –88 bytes

1. **Identify the target chunk size** – Choose a heap allocation whose size class matches the chunk that precedes `top_borders`. In FFmpeg, the buffer allocated just before `top_borders` is usually a **temporary macroblock scratch buffer** of size 64 bytes (rounded up to 0x70) or 96 bytes. Verify the size by inspecting a single‑frame decode with `gdb` or by printing the allocation size (`malloc_usable_size`).
2. **Force the same size class** – In each preceding frame, allocate a **controllable object** of that exact size and then free it *after* the frame is done. A convenient object is an `AVFrame` side‑data buffer (`av_frame_get_side_data`) that the application can request via a custom codec option (e.g., `-extra_hw_frames`). By issuing a dummy `-metadata` option the attacker can cause the decoder to allocate a side‑data buffer of the chosen size on every frame.
3. **Create a gap** – Because `top_borders` is allocated **after** the frame‑initialisation (`ff_h264_frame_start`), the layout for a given frame looks like:
   ```
   [previous frame’s temp buffers]   <-- freed before new frame start
   [new frame allocations]            <-- includes top_borders
   ```
   By ensuring that the **previous‑frame temporary buffer** remains allocated *until* the next frame’s `ff_h264_frame_start` finishes, it will become the **preceding chunk** of the newly allocated `top_borders`.
4. **Multi‑frame grooming steps**
   - **Frame N‑1:** Allocate a fake object of the target size and keep a reference to it (e.g., keep a reference to an `AVFrame` that is not yet released). This object will be the *previous* chunk.
   - **Frame N:** Trigger the normal decoding of the malicious picture containing 65 536 slices. When `ff_h264_frame_start` runs, it allocates `top_borders`; the previous chunk is exactly the fake object from Frame N‑1, located **–88 bytes** before `top_borders` because the allocator pads each chunk to 16‑byte alignment. The offset is deterministic for the chosen size class.
   - **After underflow:** The XCHG write overwrites the first 16 bytes of that previous chunk, i.e., the **tcache freelist pointer** (`fd`). Because the attacker already holds a pointer to the fake object, they can later free it, causing the poisoned `fd` to be returned on the next allocation of the same size.
5. **Final pivot:** On the *next* frame (or after a controlled allocation request), the allocator returns a chunk whose data area is at the address the attacker planted in the `fd`. The attacker then writes a **controlled structure** (e.g., a fake `AVFrame` with its `data[0]` pointer pointing to a ROP chain or `__malloc_hook`). When the decoder later accesses that structure (for example during `av_frame_unref` or when the deblocking filter reads `ref2frm`), control flow is hijacked.

**Key points:**
- The grooming only needs **two frames**: one to place the target chunk, another to allocate `top_borders` and trigger the underflow.
- Because the allocation size class is fixed, the offset `-88` is deterministic across runs on the same glibc version.
- The attacker can repeat the sequence for reliability, achieving a **stable heap layout**.

---
## 4. Alternative path – using the under‑flow as an information leak first

The XCHG macro swaps the 16‑byte value from the border cache *into* the under‑flow address **and reads the original 16 bytes back into the cache**. This gives a **read‑what‑where** primitive:
1. **Leak step:** Before the write is performed, the attacker arranges the top‑row pixel values to contain a known pattern (e.g., `0x41414141…`). After the XCHG, the cache now holds whatever previously existed at the under‑flow address – that is, the first 16 bytes of the preceding heap chunk.
2. **Interpretation:** If the previous chunk is a freed tcache entry, those 16 bytes are the **tcache `fd` pointer**. By reading it back, the attacker learns an **actual heap address** (the address of the next chunk in the tcache list). This defeats heap ASLR partially, providing a reliable heap base.
3. **Transition to write:** With the leaked address, the attacker can now craft the pixel row for a *second* under‑flow (e.g., by decoding another frame) to write a chosen value to a *different* offset, such as overwriting a function pointer in an adjacent `AVCodecContext` or a vtable pointer.
4. **Benefit:** Even if precise grooming of the -88 offset is hard, the attacker can first leak a heap pointer, then allocate a controlled object at a known offset (e.g., via `malloc`) and use a **second under‑flow** to overwrite that object’s data directly. This two‑stage approach relaxes the need for exact -88 placement; the attacker only needs *any* writable chunk adjacent to `top_borders`, which is easier to guarantee by allocating a large buffer just before the frame starts.

**Overall feasibility:** The leak‑then‑write chain is **more reliable** because the first step does not depend on the poisoned `fd`; it only requires the attacker to observe the value that already lives at the under‑flow address. Once the heap layout is known, the attacker can perform targeted allocations to bring a chosen target into the under‑flow’s reach.

---
**Summary**
- **Delivery:** Use a raw Annex B `.h264` file or an RTP/H264 stream – both survive the massive slice count.
- **Value control:** The attacker can fully dictate the 16‑byte value, enough for an arbitrary pointer.
- **Grooming:** A two‑frame heap‑grooming technique (allocate a controllable chunk in frame N‑1, trigger under‑flow in frame N) positions a target chunk exactly –88 bytes before `top_borders`.
- **Alternative:** Leverage the XCHG read side as an information leak, then perform a second under‑flow or a normal write to achieve arbitrary code execution without precise -88 placement.

---
*The analysis is derived solely from the supplied source and typical glibc ptmalloc2 behaviour; no external references were used.*