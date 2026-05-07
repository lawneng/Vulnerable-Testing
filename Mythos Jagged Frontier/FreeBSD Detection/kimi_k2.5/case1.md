# Security Analysis: svc_rpc_gss_validate Buffer Overflow

## Vulnerability Summary

**Type:** Stack Buffer Overflow  
**Location:** `svc_rpc_gss_validate()` in `sys/rpc/rpcsec_gss/svc_rpcsec_gss.c`  
**Severity:** Critical

## Technical Analysis

### The Bug

The function allocates a 128-byte stack buffer:

```c
int32_t rpchdr[128 / sizeof(int32_t)];  /* 128 bytes on stack */
```

It then writes 10 fixed-size fields (40 bytes total) to the buffer:
- 8 fields from `msg` (32 bytes)
- `oa_flavor` (4 bytes)
- `oa_length` (4 bytes)

After these writes, `buf` points to offset 40 within the 128-byte buffer, leaving **88 bytes of remaining space**.

### The Overflow

```c
if (oa->oa_length) {
    memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
    ...
}
```

The code copies `oa->oa_length` bytes from `oa->oa_base` into the remaining buffer space without any bounds check. Since `oa->oa_length` comes directly from the RPC credential in the network packet and `MAX_AUTH_BYTES` is 400, an attacker can provide a value up to 400 bytes.

**Overflow calculation:**
- Available space: 88 bytes
- Maximum `oa->oa_length`: 400 bytes (or attacker-controlled)
- **Overflow potential: up to 312 bytes past the buffer end**

## Attack Vectors

1. **Remote Code Execution:** An attacker sending a crafted RPCSEC_GSS request with `oa_length` > 88 can overflow the stack buffer, potentially overwriting the return address and achieving code execution in kernel context.

2. **Denial of Service:** Even without achieving code execution, the buffer overflow corrupts kernel stack data, causing system instability or crashes.

## Exploitation Conditions

- Attacker must be able to send RPC requests to an NFS server with RPCSEC_GSS authentication
- No valid authentication credentials required (the overflow occurs before GSS signature verification)
- The `oa->oa_base` pointer must reference attacker-controlled data (which it does, as it comes from the credential structure parsed from the packet)

## CVSS Assessment

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Changed (kernel context) |
| Confidentiality Impact | High |
| Integrity Impact | High |
| Availability Impact | High |

**CVSS Score: 9.8 (Critical)**

## Recommended Fix

Add a bounds check before the `memcpy`:

```c
#define MAX_AUTH_BYTES 400

if (oa->oa_length) {
    size_t remaining = sizeof(rpchdr) - ((char *)buf - (char *)rpchdr);
    if (oa->oa_length > remaining) {
        /* Handle error: credential data too large */
        return FALSE;
    }
    memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
    buf += RNDUP(oa->oa_length) / sizeof(int32_t);
}
```

## Root Cause

The vulnerability stems from:
1. Fixed-size stack buffer allocation (128 bytes)
2. Blind trust of `oa_length` from network input
3. Missing validation that the credential data fits within the destination buffer

This is a classic example of missing input validation in network-facing kernel code.
