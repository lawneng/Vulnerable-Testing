# Weaponization Analysis: `h264_slice_init` Constraints

## 1. Delivery Mechanism Analysis

To bypass muxer-imposed limits (like the ~8192 slice cap in MP4/MKV), the attacker must use a transport that handles raw NAL units.

- **Most Reliable: Raw Annex B Bytestream.** This is the gold standard for this attack. Files ending in `.h264` or `.264` are typically parsed as raw streams. Since there is no container metadata to validate, the FFmpeg parser will process as many NAL units as are provided until the end of the stream or an internal error.
- **RTSP/RTP Streams:** Also highly viable. RTP packets carry NAL units. Since the stream is continuous and the decoder state is persistent, the attacker can stream 65,536 slice NAL units over time. This is often the most "stealthy" way to deliver the payload to a live server.
- **HLS Segments:** While segments are often `.ts` (MPEG-TS), which has its own structural constraints, raw Annex B segments are possible and would likely survive.
- **WebRTC:** Similar to RTP, the RTP-based nature of WebRTC makes it a strong candidate for delivering the required volume of NAL units.

**Conclusion:** **Raw Annex B** is the most reliable for static files; **RTSP/RTP** is the most reliable for live targets.

## 2. Value Control (The 16-Byte Write)

The attacker's control over the 16 bytes written by `XCHG` is constrained by the H.264 reconstruction process (Prediction $\rightarrow$ Inverse Quantization $\rightarrow$ Inverse Transform).

- **Control Level:** High, but not absolute. While an attacker cannot write arbitrary bits directly (due to quantization), they can control the reconstructed pixels with high precision. By using **Intra-prediction (4x4 or 16x16 modes)** and carefully choosing the transform coefficients, they can achieve most values in the 0-255 range per byte.
- **Pointer Construction:** Writing a full 64-bit pointer (8 bytes) requires 8 consecutive bytes of specific values. Since quantization errors are small, an attacker can typically get within $\pm 1$ or $\pm 2$ of the desired value. While this might seem insufficient for a precise pointer, it is often enough to:
    - Corrupt the **LSBs of a tcache pointer**, causing a "near-miss" allocation.
    - Corrupt **chunk size metadata** (which only requires a few bits to be changed to trigger an overlap).
    - Trigger a crash (DoS) reliably.
- **Multi-Pass Refinement:** Since the attacker can repeat the attack across multiple frames, they can iteratively "massage" the heap or attempt different value combinations.

**Conclusion:** Full arbitrary pointer precision is difficult, but **metadata corruption (size fields) and partial pointer corruption (tcache poisoning)** are highly feasible.

## 3. Multi-Frame Grooming Strategy

Since `top_borders` is allocated at the start of each frame, the attacker must use a multi-frame approach to stabilize the heap.

1. **Heap Stabilization (Frames 1-N):**
   - Send frames with varying resolutions and slice counts to exhaust the `tcache` and fill existing heap holes.
   - Use a "spray" of allocations by manipulating other FFmpeg structures (e.g., creating many small `AVFrame` descriptors or using specific codec options that trigger allocations).
2. **Target Placement (Frame N+1):**
   - Trigger an allocation of a "victim" object (e.g., a `tcache` chunk of the same size as the `top_borders` allocation).
   - Control the timing such that the victim object is placed in a hole that will be immediately followed by the `top_borders` allocation in the next frame.
3. **The Trigger Frame (Frame N+2):**
   - The `top_borders` allocation occurs. Because of the previous grooming, it lands precisely aligned such that the victim object's metadata (or data) is at the -88 byte offset.
   - Deliver the 65,536 slices.
   - The `XCHG` underflow fires, corrupting the victim object placed in the previous frame.

## 4. Alternative: Info-Leak Primitive

If precise grooming for a write is too unstable, the `XCHG` primitive can be repurposed as a **Heap Info-Leak**.

- **The Mechanism:** `XCHG` is a swap. It reads 16 bytes from the target address (`top_borders[-1]`) and writes them into the border cache.
- **The Leak:** The bytes read from the heap (e.g., chunk metadata or a pointer) are now stored in the decoded pixel data of the frame.
- **Exfiltration:**
    - If the attacker can observe the decoded output (e.g., via a side-channel, a public stream, or a "heartbeat" mechanism where the decoder sends back a processed frame), they can read the leaked heap bytes directly from the pixels.
    - Even without direct output, if the decoder's behavior changes based on the leaked value (e.g., timing differences in subsequent macroblock processing), it can be used as a timing side-channel.
- **Synergy:** Once the heap base or a specific object's address is leaked, the "Grooming" phase becomes deterministic rather than probabilistic, making the subsequent write attack 100% reliable.

**Conclusion:** The `XCHG` read side is a potent info-leak that transforms the exploit from a probabilistic "shot in the dark" into a surgical RCE.
