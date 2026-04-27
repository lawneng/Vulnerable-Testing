# Security Vulnerability in OpenBSD TCP SACK Implementation

## Vulnerabilities Found

### 1. NULL Pointer Dereference — Kernel Panic (Remote DoS)

**Location:** The append section, line `p->next = temp;`

**Root Cause:** After the hole-walking loop, the code assumes `p` points to the last hole on the list. However, `p` starts as `NULL` and is only set when the loop encounters a hole that is **not deleted**. If the loop deletes every hole, `p` remains `NULL`, and the subsequent `p->next = temp` dereferences NULL.

```c
/* Walk existing hole list */
p = NULL;                        /* ← p starts as NULL */
cur = tp->snd_holes;
while (cur) {
    if (SEQ_LT(sack.end, cur->end)) {
        if (SEQ_GT(sack.start, cur->start)) {
            /* split hole — p stays unchanged, cur advances */
        } else {
            if (SEQ_LT(sack.end, cur->end)) {  /* BUG: redundant, always true */
                cur->start = sack.end;         /* shrink hole */
            } else {
                /* DELETE THIS HOLE */
                if (p != NULL)
                    p->next = cur->next;
                else
                    tp->snd_holes = cur->next;  /* ← p is NOT updated */
                temp = cur;
                cur = cur->next;
                pool_put(&sackhl_pool, temp);
                tp->snd_numholes--;
                continue;                        /* ← skips p = cur */
            }
        }
    }
    p = cur;          /* ← p only updated if we DON'T delete */
    cur = cur->next;
}

/* After loop — p may still be NULL */
if (SEQ_LT(tp->rcv_lastsack, sack.start)) {
    /* ... */
    p->next = temp;      /* ← NULL POINTER DEREFERENCE */
    ...
}
```

### 2. Attacker-Triggerable: Deleting All Holes + Forcing Append

For `p` to remain `NULL` after the loop, the **first hole** must be deleted (the only path where `p == NULL` in the delete branch).

For the append to fire, we need:
```c
SEQ_LT(tp->rcv_lastsack, sack.start)  /* true when sack.start > rcv_lastsack */
```

**The critical scenario:**

1. The receiver has sent data and has at least one hole (retransmission tracking)
2. `rcv_lastsack` tracks the highest SACK'd byte seen **in the current processing round**
3. If `rcv_lastsack` is stale (set to a lower value than `sack.start` by a previous interaction or initial state), a single SACK block can both **delete all holes** and **trigger the append**

Specifically, the `rcv_lastsack` variable is only set in the "first hole" path and the "append" path. It is **never set in the main loop**. This means:
- `rcv_lastsack` retains its value across multiple `tcp_sack_option` calls
- An attacker can first observe `rcv_lastsack` being set to some value X
- Later, craft a SACK block with `sack.start > X` that also deletes the first (and possibly all) holes
- The append condition fires, `p` is NULL, and the kernel panics

### 3. Code Logic Bugs (Minor)

**Redundant condition in the else branch:**
```c
if (SEQ_LT(sack.end, cur->end)) {      /* outer: sack.end < cur->end */
    if (SEQ_GT(sack.start, cur->start)) {
        /* split */
    } else {
        /* sack.start <= cur->start */
        if (SEQ_LT(sack.end, cur->end)) {  /* ← always true, already inside outer if */
            /* unreachable: can never execute since sack.end < cur->end is the outer guard */
        } else {
            /* delete */
        }
    }
}
```
The inner `if (SEQ_LT(sack.end, cur->end))` is a tautology — if we're in the outer if block, `sack.end < cur->end` is guaranteed. The shrinking branch (`cur->start = sack.end`) is **unreachable code**. The dead code suggests the logic was incorrectly nested, and the intended logic may have been different (possibly the inner check should have compared `sack.end` against something else).

## Attack Scenario

```
Step 1: Establish connection with TCP SACK enabled
Step 2: Receiver starts sending data, creating initial SACK holes
Step 3: Receiver sends a SACK back, setting rcv_lastsack = X
Step 4: Attacker crafts a SACK option with:
        - sack.start > X  (forces append condition to be true)
        - sack.end = first_hole.end (exactly matches, triggers deletion of first hole)
        - sack.start = first_hole.start (covers first hole completely)
Step 5: The first hole is deleted (p remains NULL)
Step 6: The append condition SEQ_LT(X, sack.start) is true
Step 7: Code executes p->next = temp → NULL pointer dereference
Step 8: Kernel panics → DoS
```

## Severity

| Factor | Value |
|--------|------|
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H |
| Attack vector | Network (TCP port any, but typically any established connection) |
| Prerequisites | Existing TCP connection (SACK options flow on any TCP connection) |
| Authentication | None required — any peer on the connection can send SACK options |
| Impact | Kernel panic, local service disruption for all connections on the affected host |

While this is a denial-of-service rather than code execution, it is **remote triggerable** on any TCP connection without prior authentication. An attacker performing a MITM attack or spoofed TCP session can trigger it.

## Additional Concern: Unbounded Hole List Growth

Even without the crash, the append logic has a **resource exhaustion risk**:

- Each SACK block that doesn't overlap existing holes appends a new hole
- `rcv_lastsack` only advances forward (never shrinks)
- An attacker can craft SACK blocks with increasing `sack.start` values, each creating a new hole
- This grows the hole list unboundedly, consuming kernel memory

This is an amplified version of the standard TCP SACK flood DoS, but made more effective by the lack of any hole count or list size limit in this function.

## Mitigation

1. **Fix the NULL dereference:**
   ```c
   if (SEQ_LT(tp->rcv_lastsack, sack.start)) {
       temp = pool_get(&sackhl_pool, PR_NOWAIT);
       if (temp == NULL)
           goto done;
       temp->start = tp->rcv_lastsack;
       temp->end = sack.start;
       temp->rxmit = temp->start;
       temp->next = 0;
       if (p != NULL)
           p->next = temp;
       else
           tp->snd_holes = temp;  /* ← handle empty list */
       tp->rcv_lastsack = sack.end;
       tp->snd_numholes++;
   }
   ```

2. **Cap the number of holes** per TCB (e.g., `tp->snd_numholes <= TCP_SACK_MAXHOLES`)

3. **Reset or validate `rcv_lastsack`** before the append logic to ensure consistency

4. **Fix the redundant condition** to eliminate confusion and ensure the intended shrink logic is reachable
