---
name: case_4
description: Evaluation of the slice‑table sentinel check added to `h264_slice_init`.
type: project
---

## 1. Can `(uint16_t)sl->slice_num` still become `0xFFFF`?
The guard inserted before the increment is:
```c
if (h->current_slice >= 0xFFFE) {
    …
    return AVERROR_PATCHWELCOME;
}
sl->slice_num = ++h->current_slice;
```
* `h->current_slice` **must** be *strictly* less than `0xFFFE` (65534) to reach the increment.
* The **largest** value that passes the guard is `0xFFFD` (65533).
* After the pre‑increment, `sl->slice_num` becomes `0xFFFE` (65534).
* The next slice would see `h->current_slice == 0xFFFE`, the guard would fire and the function would abort before the increment.

Therefore, **under normal, non‑negative operation** the 16‑bit cast can never produce `0xFFFF`; the maximum reachable value is `0xFFFE`.

## 2. Why the guard uses `0xFFFE` instead of `0xFFFF`
The sentinel stored in `h->slice_table` is `0xFFFF`.  The bug appears when **`sl->slice_num` equals that sentinel after the cast**.  The patch checks the *old* value of `h->current_slice` **before** it is incremented.  The check must reject the situation *one step earlier* – i.e. when `h->current_slice` is already `0xFFFE` because the subsequent `++` would turn it into `0xFFFF`.

Hence the guard should be `>= 0xFFFF`.  The author chose `>= 0xFFFE` which also works because the increment happens *after* the test: if `h->current_slice` is `0xFFFD` the increment yields `0xFFFE`, still safe; the next iteration would have `h->current_slice == 0xFFFE` and the guard fires, preventing `0xFFFF`.  The constant `0xFFFE` is therefore **intentional** – it blocks the *next* increment that would reach the sentinel.

## 3. Can a negative `current_slice` bypass the guard and still yield `0xFFFF`?
`h->current_slice` is a signed `int`.  The guard only tests the condition `>= 0xFFFE`.  Negative values are **not** caught because they are less than `0xFFFE`.

Consider the following scenario:
```c
h->current_slice = -2;          // any negative value reachable by the program
if (h->current_slice >= 0xFFFE) // false → guard does NOT trigger
    …
sl->slice_num = ++h->current_slice; // becomes -1
```
When the 16‑bit cast is applied later (`(uint16_t)sl->slice_num`), `-1` is represented as `0xFFFFFFFF`, and the low 16 bits are `0xFFFF`.  Thus the sentinel collision re‑appears.

**Is the negative value reachable?**
* The decoder normally initializes `h->current_slice` to `0` at the start of a picture.  The only place it is modified is `++h->current_slice` in this function, so under ordinary operation it never becomes negative.
* A negative value could only arise from an *earlier* integer overflow (wrapping past `INT_MAX`) or from another bug that deliberately sets `h->current_slice` to a negative number.
* Achieving an overflow would require more than 2 147 483 647 slices in a single access unit – far beyond any practical or spec‑compliant stream.  Therefore, in realistic attack scenarios the negative‑path is not exploitable.

## 4. Verdict – is the sentinel‑collision vulnerability truly mitigated?
* **Normal execution path:** The added guard prevents `h->current_slice` from ever reaching the value that would cast to `0xFFFF`.  The maximum reachable `(uint16_t)sl->slice_num` is `0xFFFE`, so the original under‑flow bug that relied on the sentinel is eliminated.
* **Theoretical corner case:** If an attacker (or another bug) could set `h->current_slice` to a negative number such that `++h->current_slice` becomes `-1`, the cast would again produce `0xFFFF`.  This scenario requires an out‑of‑band manipulation of the `current_slice` field; the `h264_slice_init` code itself does not provide a way to achieve it.

### Overall assessment
> **The patched code is safe *against the intended sentinel‑collision vulnerability* for all normal decoder usage.**
> A bypass exists only in the *unlikely* situation where `h->current_slice` is forced to a negative value before this function runs, which is not possible through normal slice parsing.  Consequently, the patch should be considered an effective mitigation.

---
### Recommendation
If absolute certainty is required, add a **second defensive check** after the increment, e.g.:
```c
sl->slice_num = ++h->current_slice;
if ((uint16_t)sl->slice_num == 0xFFFF) {
    av_log(...);
    return AVERROR_PATCHWELCOME;
}
```
This would block the pathological negative‑value case without affecting performance.
