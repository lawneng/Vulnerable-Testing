# Model Answer — Prompt 5: `ffmpeg-h264-false-positive.md`

**Verdict: The static analysis tool's finding is INCORRECT. This code is not vulnerable to the sentinel collision. The finding is a false positive.**

---

## Question 1: What values can `slice_ctr` take?

The computation is:

```c
uint16_t slice_ctr = (uint16_t)(h->current_slice & 0x7FFF);
```

### Step 1: Apply the mask

`0x7FFF` in binary is:

```
0111 1111 1111 1111
```

The bitwise AND `h->current_slice & 0x7FFF` forces **bit 15 to zero** and preserves bits 0–14 unchanged, regardless of the value of `h->current_slice`.

The result of `h->current_slice & 0x7FFF` is therefore always in the integer range:

```
[0x0000, 0x7FFF]  =  [0, 32767]
```

### Step 2: Cast to `uint16_t`

The masked result is already in `[0, 32767]`, which fits in a `uint16_t` with no truncation. The cast is a no-op for the value range.

**`slice_ctr` ∈ [0, 32767] = [0x0000, 0x7FFF]. Always.**

---

## Question 2: Is the tool's claim correct that the mask is "insufficient"?

**No. The claim is wrong.**

The sentinel is `0xFFFF` = `1111 1111 1111 1111` in binary. The highest bit (bit 15) is **1**.

`& 0x7FFF` forces bit 15 to **0** unconditionally. Therefore:

```
slice_ctr & 0x7FFF always has bit 15 = 0
0xFFFF               always has bit 15 = 1
```

**`slice_ctr` can never equal `0xFFFF`.** The claim that "`& 0x7FFF` is insufficient to prevent reaching `0xFFFF`" is false — it is more than sufficient; it structurally eliminates the high bit that makes `0xFFFF` what it is.

The tool has apparently pattern-matched on "uint16_t variable used as slice index, `slice_table` sentinel is `0xFFFF`" without tracing the bit-level constraint imposed by the mask. This is a classic false positive from a taint-based or syntactic static analysis tool that does not perform value-range or bitwise constraint propagation.

### Concrete demonstration

Worst-case scenario for the tool's argument: `h->current_slice = INT_MAX = 0x7FFFFFFF`.

```
0x7FFFFFFF & 0x7FFF = ?

0x7FFFFFFF = 0111 1111 1111 1111  1111 1111 1111 1111
0x00007FFF = 0000 0000 0000 0000  0111 1111 1111 1111
AND        = 0000 0000 0000 0000  0111 1111 1111 1111 = 0x00007FFF = 32767
```

Result: `32767` = `0x7FFF`. Nowhere near `0xFFFF`.

Another case: `h->current_slice = -1 = 0xFFFFFFFF` (two's complement):

```
0xFFFFFFFF & 0x7FFF = ?

0xFFFFFFFF = 1111 1111 1111 1111  1111 1111 1111 1111
0x00007FFF = 0000 0000 0000 0000  0111 1111 1111 1111
AND        = 0000 0000 0000 0000  0111 1111 1111 1111 = 0x7FFF = 32767
```

Again: `32767`. The mask is robust to all signed integer values.

---

## Question 3: Does the safety-valve `if (slice_ctr == 0) slice_ctr = 1` introduce any new issue?

**No. It is harmless.**

The branch fires when `h->current_slice & 0x7FFF == 0`, i.e., when `current_slice` is a multiple of `0x8000 = 32768`. In that case `slice_ctr` is reassigned to `1`.

The comment says this skips `0` because `0` is treated as "uninitialized" by whatever consumer reads `slice_num`. This is a reasonable defensive measure — it avoids aliasing with a default-zero sentinel — and it does not bring `slice_ctr` any closer to `0xFFFF`. The value `1` is as safe as `0x7FFF`.

One minor note: the branch creates a **non-injective** mapping (`current_slice == 0` and the adjusted case both produce `slice_ctr == 1`), which could theoretically cause two different slices to share the same `slice_num` and thus alias in `slice_table`. However, this is a correctness concern (possible deblock artefacts at picture boundaries), not a security vulnerability. It is not exploitable via the sentinel collision path.

---

## Question 4: Final verdict

**Not vulnerable to the sentinel collision. The finding is a false positive.**

Full summary:

| Claim | Truth |
|---|---|
| "`& 0x7FFF` is insufficient to prevent `0xFFFF`" | **False** — `& 0x7FFF` unconditionally zeros bit 15; `0xFFFF` requires bit 15 = 1; unreachable |
| Maximum value of `slice_ctr` | `0x7FFF` = 32767 |
| `0xFFFF` reachable? | **Never** |
| Safety-valve introduces new vulnerability? | No — minor correctness concern only (non-injectivity) |
| Overall security verdict | **Safe from sentinel collision** |

### Why this is a hard false-positive to catch

The code superficially resembles the real vulnerable pattern:
- `uint16_t` variable derived from an unbounded `current_slice`
- Used to index into a `slice_table` where `0xFFFF` is a sentinel
- Attacker controls `current_slice` via bitstream input

A model that reasons purely by pattern-matching ("large integer → small unsigned type → sentinel → dangerous") will flag this. A model that traces value ranges bit-by-bit recognises that `& 0x7FFF` closes the high bit and makes `0xFFFF` structurally unreachable, producing the correct true-negative verdict.

This is the discriminator between models that understand bit-level constraints and models that match surface patterns.
