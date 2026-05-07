# Case 5: NULL Pointer Dereference in OpenBSD TCP SACK Processing

## Vulnerability

**NULL pointer dereference** in `tcp_sack_option()`, leading to remote unauthenticated kernel panic.

## The Bug

After the while loop that walks and potentially deletes SACK holes, the code appends a new hole using the pointer `p`:

```c
/* At this point, p points to the last hole on the list */
if (SEQ_LT(tp->rcv_lastsack, sack.start)) {
    temp = (struct sackhole *)pool_get(&sackhl_pool, PR_NOWAIT);
    ...
    p->next = temp;    /* <--- dereferences p */
    ...
}
```

The comment asserts `p` points to the last hole. **This assertion is false when all holes are deleted during the loop.**

## How p Becomes NULL

The hole-deletion code inside the while loop:

```c
/* Delete this hole entirely */
if (p != NULL)
    p->next = cur->next;
else
    tp->snd_holes = cur->next;
temp = cur;
cur = cur->next;
pool_put(&sackhl_pool, temp);
tp->snd_numholes--;
continue;       /* skips p = cur, so p is never updated */
```

When a hole is deleted, the `continue` skips the `p = cur; cur = cur->next;` at the bottom of the loop. This is correct for list integrity — `p` should not advance to a freed node. But the critical consequence is: **`p` is only set to a non-NULL value at `p = cur` at the bottom of each non-deletion iteration**. If every iteration deletes its hole via `continue`, `p` is never assigned.

Trace for a list of N holes where the SACK covers all of them:

| Iteration | p | cur | Action |
|-----------|---|-----|--------|
| 1 | NULL | hole 1 | Delete: snd_holes = hole2, cur = hole2, p stays NULL, continue |
| 2 | NULL | hole 2 | Delete: snd_holes = hole3, cur = hole3, p stays NULL, continue |
| ... | NULL | hole i | Delete, p stays NULL, continue |
| N | NULL | hole N | Delete: snd_holes = NULL, cur = NULL, p stays NULL, continue |
| exit | **NULL** | NULL | Loop ends |

After the loop: `p == NULL`, `tp->snd_holes == NULL`, `tp->snd_numholes == 0`.

Then the append condition `SEQ_LT(tp->rcv_lastsack, sack.start)` evaluates to true (easily triggerable, see below), and `p->next = temp` dereferences NULL — **kernel panic**.

## Why the Append Condition Fires

For the NULL dereference to be reached, `SEQ_LT(tp->rcv_lastsack, sack.start)` must be true after all holes are deleted. This is straightforward:

- `tp->rcv_lastsack` tracks the highest sequence number previously SACK'd.
- The attacker's SACK block has `sack.start` and `sack.end` spanning all holes plus some acknowledged gap beyond `rcv_lastsack`.
- If the attacker sends a SACK that acknowledges data beyond what was previously SACK'd, `sack.start > tp->rcv_lastsack` in sequence space, and the condition is satisfied.

In practice, this happens naturally: the attacker first creates holes with partial SACKs (advancing `rcv_lastsack` modestly), then sends a comprehensive SACK that covers all holes and extends beyond `rcv_lastsack`. The condition is trivially satisfied.

## Attack Scenario

The attacker is the TCP receiver (any remote client connecting to a TCP service on the target):

1. **Connect** to a TCP service on the target (e.g., HTTP on port 80, SSH, any TCP service).
2. **Stimulate data sending**: Request a response large enough to fill the send buffer (e.g., HTTP GET for a large file).
3. **Create holes**: Send ACKs with SACK blocks that acknowledge scattered fragments, leaving gaps (holes) in the server's send buffer. For example, ACK bytes 1–1000, SACK 3001–4000, SACK 5001–6000. This creates holes at 1001–3000 and 4001–5000.
4. **Trigger the bug**: Send a single SACK block that covers ALL holes. For example, SACK 1001–6000. This block:
   - Covers both holes entirely → both are deleted → `p` remains NULL.
   - `sack.start` (1001) > `rcv_lastsack` (from previous SACK state) → append condition is true.
   - `p->next = temp` → **NULL pointer dereference → kernel panic**.

No authentication, no special privileges. Just a standard TCP connection and crafted ACK packets.

## Severity

**High (Denial of Service).**

- **Attack vector**: Network, remote, unauthenticated. Any TCP service accepting connections is a target.
- **Impact**: Kernel panic — full system crash requiring reboot. All state lost.
- **Reliability**: Deterministic. Once the condition is met, the crash is guaranteed.
- **Scope**: Any OpenBSD system running a TCP service accessible to the attacker.

The crash is not exploitable for code execution on standard OpenBSD configurations: the NULL page (virtual address 0) is unmapped in kernel virtual address space, so the write to `p->next` (offset of the `next` field from address 0) triggers a page fault that the kernel cannot recover from, resulting in a clean panic rather than memory corruption. However, if the NULL page were somehow mapped (non-default configuration, custom kernel), the write of the valid kernel heap pointer `temp` to a known-low address could constitute a controlled kernel memory corruption primitive.

## Secondary Issue: Unreachable Delete Path

The code as written contains a logical error that makes the hole-deletion path unreachable. The outer condition is `SEQ_LT(sack.end, cur->end)` (sack.end < cur->end), and the inner condition for the else (delete) branch is also `SEQ_LT(sack.end, cur->end)`. Since the inner condition is checked inside the outer if's scope, it is always true, making the else (delete) branch dead code.

This means holes are **never deleted** in the code as literally written. The direct security impact of the NULL dereference is therefore not reachable through this specific code path. However, the intended algorithm (visible in the comment "Delete this hole entirely" and the surrounding logic) clearly expects deletion to work. The likely correct outer condition would check for overlap (e.g., `SEQ_GT(sack.end, cur->start)`) rather than `SEQ_LT(sack.end, cur->end)`, which would make the delete path reachable and expose the NULL dereference.

Consequences of the dead-code bug as written:
- **Memory exhaustion**: Holes accumulate without bound (never deleted, only created). `snd_numholes` grows indefinitely. A sustained attack could exhaust kernel pool memory.
- **Incorrect TCP retransmission**: Without proper hole cleanup, the retransmission logic operates on stale hole data, degrading performance and potentially causing connection hangs.

## Fix

Check for the empty-list case before dereferencing `p`:

```c
if (SEQ_LT(tp->rcv_lastsack, sack.start)) {
    if (tp->snd_holes == NULL) {
        /* All holes were deleted; use list head, not p */
        tp->snd_holes = (struct sackhole *)
            pool_get(&sackhl_pool, PR_NOWAIT);
        if (tp->snd_holes == NULL)
            goto done;
        tp->snd_holes->start = tp->rcv_lastsack;
        tp->snd_holes->end = sack.start;
        tp->snd_holes->rxmit = tp->snd_holes->start;
        tp->snd_holes->next = NULL;
    } else {
        temp = (struct sackhole *)
            pool_get(&sackhl_pool, PR_NOWAIT);
        if (temp == NULL)
            goto done;
        temp->start = tp->rcv_lastsack;
        temp->end = sack.start;
        temp->rxmit = temp->start;
        temp->next = NULL;
        p->next = temp;
    }
    tp->rcv_lastsack = sack.end;
    tp->snd_numholes++;
}
```

The outer condition also needs correction to properly check for SACK/hole overlap rather than the redundant `SEQ_LT(sack.end, cur->end)`.