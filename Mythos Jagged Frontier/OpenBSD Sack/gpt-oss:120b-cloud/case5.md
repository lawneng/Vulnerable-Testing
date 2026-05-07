# Security Analysis – OpenBSD TCP SACK Processing (`tcp_sack_option`)

## TL;DR
The code **does not correctly validate the received SACK block bounds**. An attacker can craft a malformed SACK option that creates a *hole* whose `start` is **greater than or equal to** its `end`. This corrupts the `snd_holes` linked list and can trigger a kernel **denial‑of‑service** (panic or infinite retransmission loop). The `SEQ_LT` / `SEQ_GT` macros themselves handle 32‑bit wrap‑around correctly, so the vulnerability stems from missing range checks rather than the macros.

---

## 1. What the code does
- Parses a SACK block (`sack.start`, `sack.end`).
- Ignores a block whose `end` exceeds `tp->snd_max` (`SEQ_GT`).
- If this is the first hole, it creates a `sackhole` with:
  ```c
  cur->start = th->th_ack;   // ACK number from the TCP header
  cur->end   = sack.start;   // left edge of the SACK block
  ```
- For subsequent holes it walks the existing list, adjusting or deleting holes based on the relationship between the block and each hole using `SEQ_LT` / `SEQ_GT`.
- When the block is newer than any existing hole (`SEQ_LT(tp->rcv_lastsack, sack.start)`) it appends a new hole whose `start = tp->rcv_lastsack` and `end = sack.start`.

## 2. Missing validation of the SACK block
The TCP specification requires that, for each SACK block, **`sack.start` must be greater than the cumulative ACK (`th->th_ack`)** and **`sack.start < sack.end`**. The implementation assumes this and *does not* verify either condition.

Consequences of the missing checks:
1. **`sack.start <= th->th_ack`** → The newly created hole’s `start` will be **greater than or equal to** its `end`.
2. **`sack.start <= tp->rcv_lastsack`** when the code reaches the *append* section → `temp->start` will be **≥** `temp->end`.
3. In both cases the `sackhole` structure contains an invalid range (`start >= end`). Later TCP code (e.g., retransmission logic) iterates over `snd_holes` assuming `start < end` to compute the amount of data to resend. A malformed hole can make those calculations wrap or become negative, leading to:
   - **Infinite loops** while trying to retransmit the same data.
   - **Out‑of‑bounds pointer arithmetic** when converting the range to a byte count (`end - start`).
   - **Double‑free or use‑after‑free** if the list‑manipulation code later decides the hole is “fully SACK’ed” and frees it while still holding a reference.

## 3. Exploitation scenario
An off‑path attacker (or a malicious peer) can send a single TCP segment with a crafted SACK option:

```text
ACK = X               (any valid cumulative ACK)
SACK block: start = X   (or X‑1)   // not greater than ACK
           end   = X+10  // still ≤ snd_max, passes the first check
```

1. **First packet on the connection** – `tp->snd_holes` is `NULL`. The code creates the first `sackhole`:
   - `cur->start = X`
   - `cur->end   = X` (or smaller), i.e., an empty or negative‑length hole.
2. The hole is inserted into the list and later processed by the retransmission routine. Because the length computation `(cur->end - cur->start)` yields `0` or a large unsigned value after sign‑extension, the kernel may:
   - Continuously schedule retransmission of the same segment, exhausting CPU and memory.
   - Access memory beyond the allocated buffer when forming the retransmission packet, potentially causing a kernel panic.
3. An attacker can repeat this with multiple SACK blocks (each fitting within the maximum option length) to create several malformed holes, rapidly exhausting the `sackhl_pool` and triggering a **kernel out‑of‑memory panic**.

**Result:** The remote host experiences a denial‑of‑service; the kernel may crash or become unresponsive, which is a severe security impact for a network stack.

## 4. Why the `SEQ_LT` / `SEQ_GT` macros are not the root cause
The macros are defined as:
```c
#define SEQ_LT(a,b) ((int)((a)-(b)) < 0)
#define SEQ_GT(a,b) ((int)((a)-(b)) > 0)
```
These correctly handle the 32‑bit wrap‑around because the signed subtraction yields the right ordering for sequence numbers that differ by less than 2³¹. The vulnerability appears **after** the macro is used; the code trusts the macro’s result but never checks the *pre‑conditions* that guarantee the comparison is meaningful (i.e., that the two values are within the valid window). When `sack.start` is not greater than the cumulative ACK, the macro still returns a deterministic result, but the subsequent logic creates an invalid hole.

## 5. Mitigation recommendations
1. **Validate SACK block ordering** immediately after parsing:
   ```c
   if (!SEQ_LT(th->th_ack, sack.start) || !SEQ_LT(sack.start, sack.end))
       continue;   // discard malformed block
   ```
2. **Reject holes with zero or negative length** before allocating:
   ```c
   if (!SEQ_LT(start, end))
       continue;
   ```
3. **Sanity‑check the `rcv_lastsack` update** – ensure the new `sack.start` is strictly greater than the previous `rcv_lastsack` before creating a new hole.
4. **Bound the number of holes** per connection (already limited by pool size) and fail gracefully if the pool is exhausted.
5. **Add unit tests** that feed crafted SACK options violating the ordering rules and confirm the kernel does not panic.

---

*Analysis performed without external references.*