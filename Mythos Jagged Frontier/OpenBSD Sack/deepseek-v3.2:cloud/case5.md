# Security Vulnerability Analysis: OpenBSD TCP SACK Option Processing

## Function Overview
The `tcp_sack_option` function in OpenBSD's TCP implementation processes Selective Acknowledgment (SACK) options from incoming TCP packets. It maintains a linked list of "holes" (`snd_holes`) representing ranges of sent but unacknowledged data, updating them as SACK blocks arrive.

## Vulnerability: Sequence Number Comparison with Wrap‑Around
**Type:** Logic flaw due to incorrect signed comparison of unsigned sequence numbers.

### Root Cause
The macros `SEQ_LT(a,b)` and `SEQ_GT(a,b)` are defined as:
```c
#define SEQ_LT(a,b) ((int)((a)-(b)) < 0)
#define SEQ_GT(a,b) ((int)((a)-(b)) > 0)
```

These subtract two 32‑bit unsigned sequence numbers, cast the result to `int`, and check the sign. This works only when the two numbers differ by less than 2³¹. When they differ by more than 2³¹, the unsigned subtraction wraps modulo 2³², and the signed interpretation gives the **opposite** of the true ordering.

Example:
- `a = 100`, `b = 0xFFFFFFFF` (2³²‑1)
- `a - b` (unsigned) = `101` (since wrap)
- `(int)101` = `101` > `0`
- `SEQ_GT(100, 0xFFFFFFFF)` returns **true** (incorrect — 100 < 0xFFFFFFFF)

Similarly:
- `a = 0xFFFFFFFF`, `b = 100`
- `a - b` = `0xFFFFFF9B`
- `(int)0xFFFFFF9B` = `-101` < `0`
- `SEQ_LT(0xFFFFFFFF, 100)` returns **true** (incorrect — max > 100)

Thus, comparisons become unreliable when sequence numbers are more than 2³¹ apart — a situation that occurs naturally as 32‑bit sequence numbers wrap.

### Impact on SACK Processing
The function relies on these macros for critical decisions:

1. **Validation:** `SEQ_GT(sack.end, tp->snd_max)` may incorrectly accept a SACK block that exceeds `snd_max` (or reject a valid one).
2. **Hole traversal:** `SEQ_LT(sack.end, cur->end)` determines whether the SACK covers the beginning of a hole.
3. **Split logic:** `SEQ_GT(sack.start, cur->start)` decides whether to split a hole.
4. **Append check:** `SEQ_LT(tp->rcv_lastsack, sack.start)` decides whether to append a new hole at the end.

With broken comparisons, the algorithm may:
- Delete holes that should remain.
- Fail to delete holes that should be removed.
- Create overlapping or misordered holes.
- Corrupt the linked list (e.g., `p->next` pointing to freed memory).
- Cause infinite loops (if `cur->next` becomes `cur`).

## Attack Vectors
An attacker with the ability to send crafted TCP packets with SACK options can:

1. **Denial‑of‑Service**  
   Trigger an infinite loop in the hole‑walking `while (cur)` loop, consuming CPU and blocking the TCP connection.

2. **Memory Corruption**  
   Cause the linked list to become circular or point to freed memory (`pool_put`), leading to use‑after‑free when the list is later traversed.

3. **Bypass Congestion Control**  
   Trick the sender into believing un‑sent data has been acknowledged, allowing faster transmission than the network can handle.

4. **Resource Exhaustion**  
   Cause uncontrolled allocation of `sackhole` structures via `pool_get`, potentially exhausting kernel memory.

## Exploitation Example
Assume `snd_max` is near wrap‑around (e.g., `0xFFFFFFFF`). The attacker sends a SACK block with:
- `sack.start = 5000`
- `sack.end = 6000`

The validation `SEQ_GT(sack.end, tp->snd_max)` computes `6000 - 0xFFFFFFFF = 6001` (unsigned), which as signed `int` is positive → condition **true**, incorrectly rejecting the SACK.

If `snd_max` is small (e.g., `1000`) and `sack.end` is near wrap‑around (e.g., `0xFFFFFF00`), the same check may incorrectly **pass** a SACK that exceeds the highest sent byte.

Worse, the hole‑list manipulation can create overlapping holes or leave dangling pointers, leading to kernel panic when the list is later processed (e.g., during retransmission).

## Severity
**High** – Remote, unauthenticated denial‑of‑service (kernel panic) is likely. Memory corruption could potentially lead to arbitrary code execution, though exploitation is more difficult due to pool allocator hardening in OpenBSD.

## Recommendation
Replace `SEQ_LT`/`SEQ_GT` with a proper modular comparison:
```c
#define SEQ_LT(a,b) ((int32_t)((a)-(b)) < 0)   /* Already problematic */
/* Use instead: */
#define SEQ_LT(a,b) (((int32_t)((a)-(b))) < 0 && (a) != (b))
```
But still broken. Better: implement explicit wrap‑aware comparison functions that treat sequence numbers as modulo 2³² arithmetic.

OpenBSD may already have `SEQ_LEQ`, `SEQ_GEQ` macros that handle wrap‑around correctly; ensure all comparisons use those.