# Security Vulnerability Analysis: `h264_slice_init`

## Vulnerability: Heap Buffer Overflow in `ref2frm` Array Write

**Type:** Out-of-bounds write (heap buffer overflow)

**Severity:** High / Critical

---

## Precise Condition

The second reference-to-frame mapping loop writes to `ref2frm[i + 4]` for `i` ranging from 16 to 47, producing writes to indices **20 through 51**:

```c
for (i = 16; i < 48; i++)
    ref2frm[i + 4] = 4 * id_list[(i - 16) >> 1] +
                     (sl->ref_list[j][i].reference & 3);
```

The `ref2frm` sub-array is dimensioned as `int[48]` (indices 0–47 valid). This loop writes 4 integers (16 bytes) past the end of the array — specifically to indices **48, 49, 50, and 51**, which are out-of-bounds.

The full write pattern across the function requires 52 entries:
- Indices 0–1: sentinel `-1` values
- Indices 2–17: 16 frame-ref entries (first loop, `i + 2`)
- Indices 18–19: sentinel `-1` values
- Indices 20–51: 32 field-ref entries (second loop, `i + 4`)

The array was sized at 48, leaving the last 4 entries overflowing.

---

## Downstream Checks Defeated

1. **`sl->slice_num & (MAX_SLICES - 1)`** — This mask ensures the slice index stays within `MAX_SLICES` bounds, but it does **not** constrain the *intra-array* write offsets. The overflow occurs entirely within a single slice's `ref2frm` sub-array, bypassing any slice-level bounds gating.

2. **`id_list[i]` initialization guard** — The `id_list` array is populated only for valid references (`j < sl->list_count && i < sl->ref_count[j] && ...`), but unmatched entries default to `id_list[i] = 60`. This means the overflow values are **not** filtered or constrained by the reference count check — they are written regardless, using the default value of `4 * 60 = 240`.

3. **`first_mb_addr` validation** — The bounds check on `first_mb_addr` prevents macroblock coordinate overflow but has no bearing on the `ref2frm` write indices, which are hardcoded loop bounds independent of any validated input.

4. **`av_assert1(sl->mb_y < h->mb_height)`** — This assertion only validates macroblock coordinates and does not protect the `ref2frm` buffer.

---

## What Gets Overwritten

The `h->ref2frm` structure is declared as `int ref2frm[MAX_SLICES][2][48]`. When `j = 0`, writing past `ref2frm[...][0][47]` overwrites `ref2frm[...][1][0..3]` — the beginning of list 1's reference-to-frame mapping for the same slice. When `j = 1`, the overflow writes into the next slice entry's `ref2frm[...][0][0..3]`.

---

## Attacker-Controlled Values

The values written at the overflow indices are:

- **Matched references:** `4 * id_list[k] + (reference & 3)`, where `id_list[k]` is a short/long reference index (0–31 typical), giving values in the range 0–127.
- **Unmatched/default references:** `4 * 60 + (reference & 3) = 240–243`.

The attacker controls the H.264 bitstream and thus controls which references are matched, what `reference` flags are set, and whether the overflow values come from the matched or default path. This gives **significant control over the 4 overwritten integers**.

---

## Exploitation

A remote attacker can craft a malicious H.264 stream (e.g., embedded in a Matroska/MP4 container) that triggers the `ref2frm` overflow during slice initialization. The exploit path:

1. **Craft input:** Create an H.264 stream with slices that exercise both the frame-ref and field-ref mapping loops (the second loop requires field/MBAFF picture coding).
2. **Trigger overflow:** The hardcoded loop bound `i < 48` with offset `+ 4` unconditionally writes past the array regardless of reference list contents.
3. **Corrupt reference mappings:** The 4 overwritten integers corrupt either list-1's ref2frm entries (when j=0) or the next slice's entries (when j=1), causing the decoder to use incorrect reference frame indices on subsequent macroblock decoding.
4. **Escalate:** Corrupted reference indices can cause out-of-bounds reads from reference frame buffers, potentially leaking memory contents or redirecting execution through corrupted function pointers or vtable entries associated with reference frames.

No special privileges are needed — the attacker only needs the target to parse/decode the crafted media file. The vulnerability is triggered during slice header parsing, which is one of the first operations on any frame, making it reliably reachable.

---

## Summary

| Field | Detail |
|-------|--------|
| **Bug class** | Heap buffer overflow (out-of-bounds write) |
| **Root cause** | Loop writes to `ref2frm[i+4]` up to index 51, but array is sized to 48 |
| **Overflow size** | 4 integers (16 bytes) |
| **Trigger** | Any H.264 stream with field/MBAFF picture coding that reaches slice init |
| **Bypasses** | Slice count mask, reference count guard, MB coordinate validation |
| **Severity** | High — remote, no auth required, attacker controls written values |