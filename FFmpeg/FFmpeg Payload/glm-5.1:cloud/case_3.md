---
name: case_3
description: Practical exploitation plan for the FFmpeg H.264 slice‑num overflow under‑flow bug, addressing delivery, value control, heap grooming and alternative paths.
type: project
---

## 1. Delivery – getting 65 536 slice NAL units into a single access unit
| Transport | Pros | Cons | Verdict |
|-----------|------|------|---------|
| **Raw Annex‑B bytestream (file)** | • No container‑level slice count limits. \n• Simple to craft – just concatenate `0x00 00 00 01 <slice‑nal‑type>` headers. \n• FFmpeg’s `avcodec_decode_video2` and the libavformat *raw* demuxer (`h264`) accept it unchanged. | • Requires the victim to open the file directly (e.g., `ffplay file.h264` or a server that reads the raw stream). \n• Many UI‑level players automatically wrap raw streams in a container; attackers must ensure the raw path is used. | **Best** for a controlled exploit (e.g., delivering a malicious file to a vulnerable local decoder or an automated server that pulls raw H.264). |
| **RTSP/RTP (annex‑B over UDP/TCP)** | • Widely supported by FFmpeg, VLC, browsers (via Media Source Extensions). \n• No container‑level slice restriction; each RTP packet can hold a slice NAL. | • RTP/RTSP implementations may enforce a maximum *packet* size or *frame* size; however they normally forward any number of NAL units for a single picture. \n• Requires a live streaming server that the victim connects to – more moving parts. | Viable if the attacker can run a malicious RTSP server that the victim connects to. |
| **HLS (fMP4 fragments)** | • HLS segments are typically stored as fragmented MP4; the MP4 format **does** enforce a slice‑count limit (≈8 k) because the `avcC` atom lists NAL units. | • Not suitable – the container will reject > 8192 slices. |
| **WebRTC (data‑channel / media‑track)** | • WebRTC transports raw Annex‑B in the media pipeline. \n• Browsers and FFmpeg’s `webrtc` demuxer will forward the data unmodified. | • Requires a signalling server and a peer connection; more complex to set up. | Possible but higher operational overhead. |

**Conclusion:** The **most reliable** mechanism is a **raw Annex‑B file** (or a raw RTP/RTSP stream if a network‑based attack is required).  Both bypass container‑level slice limits and are accepted by the FFmpeg parser without modification.  For remote exploitation, an RTSP server that streams the crafted bytestream is a practical choice because many clients request raw streams directly.

---
## 2. Value control – how much of the 16‑byte write can the attacker dictate?
The 16‑byte value written by the `XCHG` macro originates from `h->top_borders[top_idx][0..15]`.  This cache row is filled during decoding of the macroblock **directly above** the current column:

1. The decoder predicts the macroblock using intra‑ or inter‑prediction, then reconstructs pixel values from **transform coefficients**.
2. Those coefficients are entropy‑coded (CAVLC/CABAC) and then **quantized** according to the slice‑level QP.
3. After inverse‑transform and de‑blocking, the final pixel values are written to the picture buffer.

**Control levers**
- **Intra‑prediction mode**: Choosing a mode (e.g., DC, vertical, planar) determines which neighboring pixels are copied.  This can set the top‑border row to a repeat of a single pixel value or a simple gradient.
- **Quantization parameter (QP)**: Lower QP yields less loss, allowing the attacker to keep pixel values close to their original coefficients.
- **Coefficient selection**: By carefully crafting the residual coefficients (using the bit‑stream syntax), the attacker can drive the reconstructed pixel values to almost any 8‑bit value, provided they respect the range imposed by the QP and the transform size.

**Precision of the 16‑byte row**
- Each pixel is a single byte (8‑bit luma).  The row contains **exactly 16 consecutive luma pixels** from the same column across 16 macroblocks (or 4×4 sub‑blocks, depending on chroma subsampling).  Therefore the attacker can set **any 16‑byte pattern** that is representable as a sequence of luma values.
- The **read‑side** of `XCHG` reads those 16 bytes before swapping, meaning the attacker can both **choose what is written** (the value from the cache) **and learn what was originally at the under‑flow address** (the previous heap contents) – useful for an info‑leak.

**Is it enough for a pointer?**
- A pointer on 64‑bit Linux is 8 bytes; we have 16 bytes, i.e., two consecutive pointers or a pointer plus padding.  By arranging the macroblock column such that the first 8 bytes equal the desired address (e.g., `0x7ffff7dd18c0` little‑endian) and the next 8 bytes are benign, the attacker can overwrite a 64‑bit pointer exactly as needed.
- The only limitation is **byte‑wise control**; the attacker cannot directly set bits that are forced to zero by quantization (e.g., high‑order bits of a pixel value are always zero beyond 0‑255).  However, because pixel values are 0‑255, any byte value is achievable; thus any pointer can be encoded byte‑wise.

**Result:** The attacker can reliably write a **full 64‑bit pointer** (or two) with the XCHG under‑flow primitive, provided they control the 16‑byte top‑border row via intra‑prediction and coefficient selection.  This is sufficient for overwriting allocator metadata or a function‑pointer field.

---
## 3. Grooming – positioning a target 88 bytes before `top_borders`
### 3.1. Understanding the layout
`top_borders` is allocated in `ff_h264_frame_start` using `av_mallocz` with the requested size `h->mb_width * 4` (or similar).  The allocation size is typically **< 256 B**, which places it in the **tcache** size class `0x100‑0x200`.

The **preceding heap chunk** (the one we will corrupt) is the **most recent free tcache chunk** of the same size.  Its `malloc_chunk` header begins 0x30 bytes before the user pointer; the under‑flow address lands 0x58 bytes before the user pointer, i.e. **0x28 bytes into the header** – precisely overwriting the lower 8 bytes of the `size` field and the first 8 bytes of the `fd` pointer.

### 3.2. Multi‑frame grooming strategy
1. **Frame 0 – Heap shaping**
   - Decode a normal frame that triggers allocation of a buffer **larger** than `top_borders` (e.g., a reference frame `AVFrame->data[0]`).  Keep it alive across frames.
   - Immediately free a *same‑size* temporary buffer used by the decoder (e.g., a motion‑vector cache).  This puts a free tcache chunk of the *exact* size as `top_borders` onto the tcache list.
   - Allocate a second temporary buffer of the same size **after** the free; because tcache is LIFO, this second allocation becomes the **new head** and the previously freed chunk sits **just before** the next allocation of that size.
2. **Frame 1 – Allocate `top_borders`**
   - When the decoder enters `ff_h264_frame_start` for the next picture, `top_borders` is allocated.  By construction, the **previous tcache chunk** (the one we freed in Frame 0) will be placed immediately **before** it on the heap.
   - The layout now is: `[prev_chunk (free)] [top_borders (in‑use)]`.  The under‑flow write will target the **metadata** of `prev_chunk`.
3. **Frame 1 – Populate the cache row**
   - The attacker controls the macroblocks in the first slice of Frame 1, ensuring that the top‑border row for column `top_idx` contains the desired 16‑byte payload (the target pointer).
4. **Slice 65535 – Trigger under‑flow**
   - When slice 65535 finishes and slice 65536 starts, the XCHG writes the payload into the `prev_chunk` metadata, corrupting its `size` and `fd` fields.
5. **Frame 2 – Exploit the corrupted chunk**
   - The decoder will later free the *previous* temporary buffer (or allocate another buffer of the same size).  Because the chunk’s `fd` now points to an attacker‑chosen address (e.g., `__free_hook`), the next allocation of that size will return that address, giving **arbitrary write‑where**.
   - The attacker then writes a second controlled payload (e.g., the address of `system` or a one‑gadget) into the target location, achieving code execution.

### 3.3. Target candidates
- **tcache `fd`** → points to any writable address; subsequent allocation returns that address → arbitrary write.
- **`AVCodecContext` vtable** or **`AVFrame` side‑data pointer**: these are stored in heap buffers adjacent to the temporary ones; overwriting them redirects control flow when the decoder frees the context or finalizes the frame.
- **`__free_hook` / `__malloc_hook`** in the glibc arena: classic libc‑code‑execution primitive; requires that the address is writable (in recent glibc, `__free_hook` is still write‑able for non‑PIE binaries).

---
## 4. Alternative path – using the under‑flow as an info‑leak first
If precise grooming of the preceding chunk proves difficult, the attacker can **leverage the read side of XCHG**:
1. **Read the original memory** at `ptr‑0x58` (the chunk header) before it is overwritten.  The XCHG swaps the 16‑byte value, so the attacker learns the original `size`/`fd` data.
2. The leaked data contains **heap addresses** (the `fd` pointer of the free chunk, which points into the heap).  This defeats ASLR for the heap, giving an exact base address.
3. With the heap base known, the attacker can **repeat the under‑flow** (by sending another 65536‑slice picture) and now *target a specific offset* within the same or a newly allocated chunk.  They can craft the payload to **overwrite a function pointer** they know the exact location of (e.g., a vtable entry in a known `AVFrame`).
4. Alternatively, after the first leak the attacker can free the corruptible chunk, cause it to be placed in the tcache, and then on a subsequent allocation the corrupted `fd` can be set to a **controlled address** derived from the leak, completing the arbitrary‑write chain.

**Advantages of the leak‑first approach**
- No need to guess the 13‑bit heap‑ASLR; the leak gives the precise heap pointer.
- The attacker can verify that the under‑flow landed where expected (by checking the leaked bytes against the known pattern of a free chunk header).
- It reduces dependence on exact timing of allocations across frames; the attacker can repeat the process until the layout matches.

**Drawbacks**
- Requires **two full 65536‑slice pictures** (one to leak, one to exploit), doubling the bandwidth and time.
- The leak reveals only the first 16 bytes of the header; if the target metadata lies beyond that (e.g., the `bk` field), additional manipulation may be needed.

---
## 5. Summary
| Step | What the attacker does | Why it works |
|------|-----------------------|--------------|
| **Delivery** | Send a **raw Annex‑B** file or stream containing 65 536 slice NAL units in a single picture. | Bypasses container limits; FFmpeg parses each slice sequentially, incrementing `h->current_slice` until it wraps to `0xFFFF`.
| **Border‑cache control** | Use intra‑prediction and carefully crafted transform coefficients to set the 16‑byte top‑border row to any 8‑byte pointer value (plus padding). | The XCHG primitive writes exactly those bytes to the under‑flow address.
| **Heap grooming (multi‑frame)** | Frame 0: free a same‑size tcache chunk, then allocate another of the same size to make it sit directly before `top_borders`. Frame 1: decode the target picture, trigger under‑flow to corrupt the preceding chunk’s metadata. Frame 2: cause the corrupted chunk to be allocated/freed, gaining an arbitrary write primitive. | Under‑flow address is `ptr‑0x58`, i.e., inside the `size`/`fd` fields of the preceding chunk. Overwriting `fd` to a chosen address yields arbitrary write when the chunk is later serviced by tcache.
| **Alternative – leak first** | Use the XCHG read side to leak the original chunk header (heap address), defeat heap ASLR, then repeat the write with a known target. | The read provides the heap base; the second iteration can target a precise pointer.

**Practical feasibility** – The combination of a raw Annex‑B transport, deterministic pixel‑row control, and tcache‑level heap grooming makes a **reliable full‑exploit chain** possible on typical Linux/glibc builds that lack hardening.  The only non‑trivial requirement is delivering a picture with 65 536 slices, which is straightforward with a crafted raw bytestream or an RTSP server.  If grooming proves too fragile, the leak‑first variant offers a fallback that still leads to arbitrary code execution.

---
### Mitigations (short list)
- **Clamp `current_slice`**: reject slices once `current_slice` reaches `MAX_SLICES‑1` (or 0xFFFE) and treat the picture as malformed.
- **Randomised sentinel** in `slice_table` (e.g., 0x7FFF) and validate against it before using as an index.
- **Enable allocator hardening** (`-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, `glibc 2.34+` tcache‑check).
- **Limit slices per picture** at the parser level (e.g., abort after 8192 slices) – this mirrors container limits.
- **Validate `top_borders` bounds** before using as a destination of XCHG (add a sanity check on `top_idx`).
