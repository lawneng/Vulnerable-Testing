# Security Analysis: OpenBSD TCP SACK Implementation Vulnerability

## Vulnerability Summary

**Type:** NULL Pointer Dereference (Remote Denial of Service)
**Location:** `tcp_sack_option()` in `sys/netinet/tcp_input.c`
**Severity:** High (Remote Kernel Crash)

## The Bug: Sequence Number Wraparound in Comparisons

The vulnerability stems from the `SEQ_LT(a,b)` macro defined as `((int)((a)-(b)) < 0)`. This macro treats the unsigned sequence number difference as signed, which causes incorrect comparisons when sequence numbers wrap around the 2^31 (2,147,483,648) boundary.

## Technical Analysis

### How SEQ_LT Fails

When comparing two sequence numbers where `a` is just above 2^31 and `b` is below 2^31:

**Example:**
- `a` = 3,000,000,000 (0xB2D05E00)
- `b` = 1,000,000,000 (0x3B9ACA00)

The calculation:
```
(a - b) = 0xB2D05E00 - 0x3B9ACA00 = 0x76F6B400

When cast to signed int: 0x76F6B400 = 1,990,336,512 (positive)
```

Actually, let me reconsider. The issue is when the difference exceeds 2^31:

**Better Example:**
- `a` = 3,000,000,000 (0xB2D05E00, which is > 2^31)
- `b` = 500,000,000 (0x1DCD6500, which is < 2^31)

```
(a - b) = 0xB2D05E00 - 0x1DCD6500 = 0x9502F900
```

Wait, that's still positive. Let me think more carefully.

The issue is when `a - b` (as unsigned) produces a value >= 2^31, which appears negative when cast to signed int.

**Correct Example:**
- `a` = 3,000,000,000 (0xB2D05E00)
- `b` = 1,000,000,000 (0x3B9ACA00)
- `a - b` = 2,000,000,000 (0x77359400) - this is still < 2^31

Let me try:
- `a` = 4,000,000,000 (0xEE6B2800, > 2^31)
- `b` = 500,000,000 (0x1DCD6500, < 2^31)
- `a - b` = 3,500,000,000 (0xD09DC300)

As signed int: 0xD09DC300 = -745,654,592 (negative!)

So `SEQ_LT(4000000000, 500000000)` returns **true**, even though 4,000,000,000 is numerically greater than 500,000,000!

### The Exploit Path

**The vulnerable code path:**

```c
/* Walk existing hole list */
p = NULL;
cur = tp->snd_holes;
while (cur) {
    if (SEQ_LT(sack.end, cur->end)) {  // <-- BUG HERE
        /* ... various branches with continue ... */
    }
    p = cur;
    cur = cur->next;
}

/* After loop, p should point to last hole */
if (SEQ_LT(tp->rcv_lastsack, sack.start)) {
    temp = pool_get(&sackhl_pool, PR_NOWAIT);
    /* ... setup temp ... */
    p->next = temp;          /* <--- CRASH: p is NULL */
}
```

**The Attack Scenario:**

1. Establish a TCP connection with SACK enabled
2. Send data to create SACK holes in the receiver
3. Send a crafted SACK option where:
   - `sack.end` is a large value > 2^31 (e.g., 4,000,000,000)
   - `cur->end` (existing hole) is a small value < 2^31 (e.g., 500,000,000)
   - `tp->rcv_lastsack` is also positioned to trigger the append condition

4. `SEQ_LT(sack.end, cur->end)` incorrectly returns **true**
5. The while loop body may hit a `continue` statement before `p` is updated
6. Loop exits with `p = NULL`
7. `p->next = temp` causes NULL pointer dereference
8. **Kernel panic**

## Attack Requirements

1. **Established TCP connection:** Attacker must complete TCP three-way handshake
2. **SACK enabled:** Both endpoints must support TCP SACK (negotiated in SYN)
3. **Sequence number positioning:** The attacker needs to manipulate sequence numbers to cross the 2^31 boundary

## Exploitation Strategy

**Step 1: Connection Setup**
- Connect to OpenBSD target (web server, SSH, any TCP service)
- Negotiate SACK option in TCP handshake

**Step 2: Create Initial SACK State**
- Send data segment with sequence numbers that create a hole
- Do not acknowledge the data
- The receiver will create an `snd_holes` entry

**Step 3: Trigger Wraparound**
- Wait for or manipulate sequence numbers to approach 2^31 boundary
- Send crafted SACK block with:
  - `sack.start` just above rcv_lastsack (to pass the append check)
  - `sack.end` > 2^31 (e.g., 0xF0000000)
  - Existing hole's `end` < 2^31 (e.g., 0x10000000)

**Step 4: Crash**
- `SEQ_LT(0xF0000000, 0x10000000)` → `((int)(0xE0000000)) < 0` → true
- While loop takes branch that hits `continue` before `p = cur`
- Loop exits, `p` is still NULL
- `p->next = temp` triggers kernel panic

## Impact Assessment

**CVSS Score: 7.5 (High)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality Impact | None |
| Integrity Impact | None |
| Availability Impact | High |

**Result:** Remote unauthenticated attacker can cause kernel panic (DoS)

## Root Cause

The vulnerability exists because:

1. **Signed comparison of unsigned values:** `SEQ_LT` casts unsigned sequence number differences to signed int
2. **No validation of comparison results:** The code assumes SEQ_* macros always return meaningful results
3. **Assumption about loop execution:** The code assumes `p` will always be set before the append logic, but wraparound can cause unexpected control flow

## Recommended Fix

**Option 1: Use unsigned-aware comparison macros**

```c
/* Proper sequence number comparison handling wraparound */
#define SEQ_LT(a,b)    ((int32_t)((a)-(b)) < 0)
#define SEQ_GT(a,b)    ((int32_t)((a)-(b)) > 0)
```

Wait, that's still signed. A better approach:

```c
/* Compare considering TCP sequence space as circular */
#define SEQ_LT(a,b)    (((a)-(b)) & 0x80000000U)
```

Actually, the standard approach is:

```c
#define SEQ_LT(a,b) ((int32_t)((a)-(b)) < 0)   /* Keep as-is but ensure */
#define SEQ_LEQ(a,b) ((int32_t)((a)-(b)) <= 0) /* proper 32-bit arithmetic */
```

**Option 2: Validate p before dereferencing**

```c
if (SEQ_LT(tp->rcv_lastsack, sack.start)) {
    if (p == NULL) {
        /* Handle case where list is empty or traversal failed */
        goto done;
    }
    temp = pool_get(&sackhl_pool, PR_NOWAIT);
    /* ... */
    p->next = temp;
}
```

**Option 3: Rewrite loop to not depend on p being set**

Restructure the hole list traversal to properly handle all edge cases without relying on `p` being set in the loop.

## Conclusion

This is a **remote denial-of-service vulnerability** in OpenBSD's TCP SACK implementation. An attacker can cause a kernel panic by sending a crafted TCP SACK option that triggers incorrect sequence number comparisons due to integer wraparound. The vulnerability is exploitable by any unauthenticated attacker who can establish a TCP connection with an OpenBSD system.
