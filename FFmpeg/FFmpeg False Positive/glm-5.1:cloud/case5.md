# False-Positive Discrimination Analysis

## 1. Complete Value Range of `slice_ctr`

The computation is:

```c
uint16_t slice_ctr = (uint16_t)(h->current_slice & 0x7FFF);
```

`0x7FFF` in binary is `0111 1111 1111 1111` — 15 bits set, bit 15 clear. The AND mask preserves only the low 15 bits of `current_slice` and zeroes bit 15 and all higher bits.

Regardless of `h->current_slice`'s value (any 32-bit `int`), the result of `& 0x7FFF` is always in the range **`0x0000` to `0x7FFF`** (0 to 32767). The cast to `uint16_t` is lossless here because the masked value already fits in 16 bits.

| `current_slice` (example) | `& 0x7FFF` result | `(uint16_t)` result |
|---------------------------|-------------------|---------------------|
| 0 | 0x0000 | 0x0000 |
| 1 | 0x0001 | 0x0001 |
| 32767 (0x7FFF) | 0x7FFF | 0x7FFF |
| 32768 (0x8000) | 0x0000 | 0x0000 |
| 65534 (0xFFFE) | 0x7FFE | 0x7FFE |
| 65535 (0xFFFF) | 0x7FFF | 0x7FFF |
| -1 (0xFFFFFFFF) | 0x7FFF | 0x7FFF |
| -2 (0xFFFFFFFE) | 0x7FFE | 0x7FFE |

**Maximum value of `slice_ctr`: `0x7FFF` (32767). It can never reach `0xFFFF`.**

The sentinel value `0xFFFF` has bit 15 set (value `1111 1111 1111 1111`). The mask `0x7FFF` unconditionally zeroes bit 15. There is no input to the AND operation that produces a result with bit 15 set. This is an arithmetic certainty, not a probabilistic property.

---

## 2. Is the "Insufficient Mask" Claim Correct?

**No. The claim is incorrect.** The static analysis tool has pattern-matched on "mask + sentinel + uint16_t" without tracing the actual bit-level arithmetic.

Detailed bit-pattern proof:

To produce `0xFFFF` from `x & 0x7FFF`, we would need:

```
x & 0x7FFF = 0xFFFF
```

For any bit position where the mask has a 0, the AND result is 0 regardless of `x`. The mask `0x7FFF` has a 0 at bit position 15. Therefore:

```
result bit 15 = (x bit 15) AND (mask bit 15) = (x bit 15) AND 0 = 0
```

But `0xFFFF` has bit 15 = 1. This is a **logical contradiction**. No value of `x` satisfies this equation. The mask is sufficient by construction.

The tool likely confused `0x7FFF` (15-bit mask, max `0x7FFF`) with `0xFFFF` (16-bit mask, max `0xFFFF`), or assumed that a `uint16_t` cast after masking could somehow re-introduce the cleared bit — which it cannot, because the cast only widens or narrows the already-masked value without modifying bits.

---

## 3. Safety-Valve Branch: `if (slice_ctr == 0) slice_ctr = 1`

This branch handles the case where `current_slice & 0x7FFF == 0`, which occurs when `current_slice` is a multiple of 32768 (0, 32768, 65536, etc.). It maps 0 to 1, because slice number 0 is conventionally reserved as "uninitialized" in the decoder (the `slice_table` is initialized to `0xFFFF`, and value 0 might have special meaning depending on downstream checks).

**Does this branch introduce any new issue?**

No. It maps one value (0) to another value (1), both well below the sentinel. The only effect is that slice numbers cycle through `1, 2, ..., 32767, 1, 2, ...` instead of `0, 1, ..., 32767, 0, 1, ...`. This has two consequences:

1. **No sentinel collision:** Both 0 and 1 are far from `0xFFFF`. The branch does not affect the maximum value.

2. **Aliasing:** After 32767 slices, the counter wraps to 0 → mapped to 1, so `slice_num == 1` appears twice in the same access unit. Downstream deblock logic compares `slice_table[mb_xy]` against the current `slice_num` to determine if two macroblocks belong to the same slice. If two slices share the same `slice_num == 1`, the deblocker may incorrectly treat their shared border as intra-slice, enabling deblock filtering across a slice boundary that should be treated as inter-slice.

   This is a **correctness bug** (incorrect deblocking at slice boundaries), not a security vulnerability. It produces visual artifacts (wrong loop-filter strength at slice boundaries after 32767 slices) but does not cause out-of-bounds memory access, since the deblock filter still operates on valid macroblock coordinates and valid reference data.

---

## 4. Final Verdict

**This code is NOT currently vulnerable to the `slice_table` sentinel collision.** The `& 0x7FFF` mask mathematically guarantees that `slice_ctr` is at most `0x7FFF`, which is `32767` — well below the sentinel `0xFFFF` (65535). The mask clears bit 15, which is the distinguishing bit between valid slice numbers and the sentinel value. No input, including negative values of `current_slice`, can produce `0xFFFF` after this mask.

The static analysis tool's finding is a **false positive**. It likely triggered on the superficial pattern "uint16_t slice counter + 0xFFFF sentinel in same data structure" without tracing the bitwise AND that structurally prevents the collision.

### Fragility note

While the code is safe *as written*, two architectural fragilities are worth noting:

1. **Mask is not self-documenting.** The choice of `0x7FFF` implicitly depends on the sentinel being `0xFFFF`. If the sentinel were ever changed to a value in the range `[0x8000, 0x7FFF]` (which would itself be unusual), the mask would no longer be sufficient. A defensive comment or a `static_assert` linking the mask to the sentinel value would make the invariant explicit.

2. **Slice number aliasing after 32767 slices.** The 15-bit counter wraps and reuses slice numbers, causing the deblock filter to incorrectly treat distinct slices as same-slice at shared borders. This is a correctness degradation (visual artifacts) after 32767 slices in a single access unit, not a memory safety violation. It could be fixed by using a 14-bit counter (`& 0x3FFF`) and reserving `0x7FFF` as a second sentinel, but the current 15-bit mask is sufficient for security purposes given the `0xFFFF` sentinel.

**Neither fragility constitutes a current vulnerability. The code is a true negative.**