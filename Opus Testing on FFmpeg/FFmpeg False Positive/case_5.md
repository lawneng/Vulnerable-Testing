# H.264 Slice-Counter Analysis — Static Analysis Finding Triage

**Target:** Alternative `compute_slice_num()` implementation
**Tool finding:** *"`slice_ctr` is derived from attacker-controlled `current_slice`; masking with `0x7FFF` is insufficient to prevent `(uint16_t)slice_ctr` from reaching the sentinel value `0xFFFF`."*
**Verdict:** **FALSE POSITIVE** — not currently vulnerable to the `slice_table` sentinel collision.

---

## Code Under Review

```c
static inline uint16_t compute_slice_num(H264Context *h)
{
    uint16_t slice_ctr = (uint16_t)(h->current_slice & 0x7FFF);

    if (slice_ctr == 0)
        slice_ctr = 1;

    return slice_ctr;
}

sl->slice_num = compute_slice_num(h);
h->slice_table[mb_xy] = sl->slice_num;
```

---

## 1. Value-Set Trace for `slice_ctr`

The masking operation is the controlling step:

```
slice_ctr = (uint16_t)(h->current_slice & 0x7FFF)
```

`0x7FFF` is the bitmask `0111 1111 1111 1111` — exactly the low 15 bits set, bit 15 (the 0x8000 bit) clear.

For **any** value of `h->current_slice`, regardless of its type, sign, or attacker control, the bitwise AND forces:

- Bits 0–14: pass through (may be 0 or 1)
- Bit 15: **forced to 0**
- Bits 16+: discarded by the AND, then by the `uint16_t` truncation

Therefore the result of `h->current_slice & 0x7FFF` is mathematically bounded to the closed interval:

```
[0x0000, 0x7FFF]  ==  [0, 32767]
```

The subsequent `(uint16_t)` cast does not widen the range — the value already fits in 16 bits and is non-negative, so the cast is a no-op on the bit pattern.

After the `== 0` guard remaps `0` to `1`, the final achievable set is:

```
{1} ∪ [1, 0x7FFF]  ==  [0x0001, 0x7FFF]  ==  [1, 32767]
```

**Maximum value of `slice_ctr`: `0x7FFF` (32767).**

**Can it ever equal `0xFFFF`?** **No.** Reaching `0xFFFF` would require bit 15 to be set. The mask `& 0x7FFF` unconditionally clears bit 15 on every code path before any value is returned or stored. There is no path that re-sets it.

---

## 2. Is the Mask "Insufficient"? — Concrete Bit Patterns

The tool claims `& 0x7FFF` cannot prevent the result from reaching `0xFFFF`. This is **incorrect**. Worked examples with the most adversarial inputs:

| `h->current_slice` (input)        | binary (low 16 bits)      | `& 0x7FFF`            | result   |
|-----------------------------------|---------------------------|-----------------------|----------|
| `0xFFFF` (all ones)               | `1111 1111 1111 1111`     | `0111 1111 1111 1111` | `0x7FFF` |
| `0xFFFFFFFF` (32-bit all ones)    | `...1111 1111 1111 1111`  | `0111 1111 1111 1111` | `0x7FFF` |
| `0x8000` (only sentinel-ish bit)  | `1000 0000 0000 0000`     | `0000 0000 0000 0000` | `0x0000` -> remapped to `0x0001` |
| `0x7FFF`                          | `0111 1111 1111 1111`     | `0111 1111 1111 1111` | `0x7FFF` |
| `-1` (signed int)                 | `...1111 1111 1111 1111`  | `0111 1111 1111 1111` | `0x7FFF` |

The sentinel `0xFFFF` is `1111 1111 1111 1111`. To produce it, **bit 15 must be 1**. The AND with `0x7FFF` (`0111...`) guarantees bit 15 is `0` in the output for every possible input.

```
target sentinel : 1111 1111 1111 1111  (0xFFFF)
mask 0x7FFF     : 0111 1111 1111 1111
AND result bit15: 1 AND 0 = 0   --> result MSB always 0 --> can never be 0xFFFF
```

**The mask is sufficient. The tool's claim is wrong.** This is a textbook pattern-match false positive: the tool flagged `uint16_t` + `0xFFFF` proximity without tracing that the dominating `& 0x7FFF` removes the only bit that could ever collide with the sentinel.

---

## 3. The `if (slice_ctr == 0) slice_ctr = 1` Safety Valve

This branch is **harmless** and is, in fact, defensively useful:

- `slice_num == 0` would be ambiguous with an uninitialized/zero-cleared table entry in some comparison contexts; remapping `0 -> 1` avoids that.
- It does **not** introduce any new collision: it maps into `1`, which is already a legal in-range slice number well below the sentinel.
- It cannot overflow, wrap, or push the value toward `0xFFFF`.
- It only ever fires when the masked input was exactly `0`, a deterministic and benign case.

No new issue. It strictly shrinks the output range (removes `0`), making the code marginally safer, not riskier.

---

## 4. Final Verdict

**Not currently vulnerable** to the `slice_table` sentinel collision.

- `slice_ctr` is provably bounded to `[1, 0x7FFF]`.
- The sentinel `0xFFFF` is unreachable on every path.
- The values stored into `slice_table[mb_xy]` can never equal the `memset(..., -1, ...)` sentinel, so the downstream deblock comparison `slice_table[top_xy] == current_slice` cannot be tricked into treating an uninitialized/spare entry as a valid same-slice neighbour via this routine.

This is a **true negative** — the static analysis finding is a **false positive** driven by surface pattern-matching (`uint16_t` near `0xFFFF`) rather than value-flow analysis.

### Secondary concerns worth noting (fragility, not exploitable bugs)

While the code is safe *as written*, the analysis would be incomplete without these caveats:

1. **Silent truncation / aliasing of distinct slices.** Masking to 15 bits means `current_slice` values that differ only in bits >= 15 collapse to the same `slice_num` (e.g. `0x00010005` and `0x00008005` -> wait, more precisely any two slices whose low 15 bits match alias). In a legitimately huge stream this could cause two genuinely different slices to share a `slice_num`, which *could* re-enable false same-slice neighbour matches. In practice `current_slice` is bounded far below `0x7FFF` by per-frame slice limits, so this is not reachable today — but it is a latent fragility if upstream bounds ever change.

2. **Implicit dependence on external bounds.** The safety relies on the mask, not on validating `current_slice` against the real max slice count. A defense-in-depth version should clamp/validate `current_slice` against `mb_height`/configured slice limits rather than blind-masking, so the relationship between `slice_num` and the actual decode state stays well-defined.

3. **Sentinel coupling is undocumented.** The code never references `0xFFFF` explicitly; its correctness depends on the invariant "produced values < sentinel." A comment asserting `slice_num <= 0x7FFF < 0xFFFF` would prevent a future refactor (e.g. widening the mask to `0xFFFF` or changing the cast) from silently reintroducing the real collision.

**Bottom line:** Reject the tool's high-severity finding. The mask is sufficient and the sentinel is unreachable. Track items (1)–(3) as code-quality / robustness improvements, not as active vulnerabilities.


## Result

Pass.

Core verdict correct. Concludes false positive / not vulnerable, for the right reason.
Bit-level reasoning correct. Correctly traces & 0x7FFF → bit 15 forced to 0 → range [0, 0x7FFF], sentinel 0xFFFF (bit 15 = 1) structurally unreachable. The "1 AND 0 = 0 → MSB always 0" framing is exactly the discriminating insight, not hand-waving.
Edge cases covered. Tests 0xFFFFFFFF, -1, 0x8000, 0x7FFF — matches the model answer's worst-case rigor.
Cast and safety valve handled. Correctly calls the (uint16_t) cast a no-op and the == 0 remap harmless / defensively useful, not a new vulnerability.
Downstream reasoning bonus. It goes further than the model answer by tying the conclusion back to the actual slice_table sentinel comparison and memset(..., -1), which strengthens the "why this matters" link.s
