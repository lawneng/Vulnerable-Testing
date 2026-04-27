# Security Vulnerability: Stack Buffer Overflow in `svc_rpc_gss_validate`

## Summary

**Severity: Critical (Remote Code Execution)**

`svc_rpc_gss_validate()` performs an unchecked `memcpy()` into a 128-byte fixed-size stack buffer, allowing an unauthenticated remote attacker to achieve arbitrary kernel code execution.

## Vulnerable Code

```c
int32_t rpchdr[128 / sizeof(int32_t)];  /* 128 bytes on stack */
...
buf = rpchdr;
IXDR_PUT_LONG(buf, msg->rm_xid);
IXDR_PUT_ENUM(buf, msg->rm_direction);
IXDR_PUT_LONG(buf, msg->rm_call.cb_rpcvers);
IXDR_PUT_LONG(buf, msg->rm_call.cb_prog);
IXDR_PUT_LONG(buf, msg->rm_call.cb_vers);
IXDR_PUT_LONG(buf, msg->rm_call.cb_proc);
IXDR_PUT_LONG(buf, oa->oa_flavor);
IXDR_PUT_LONG(buf, oa->oa_length);   /* 32 bytes written total */

/* OVERFLOW HERE: no bounds check on oa->oa_length */
memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
buf += RNDUP(oa->oa_length) / sizeof(int32_t);
```

## Detailed Analysis

### The flaw

`rpchdr` is a **128-byte fixed stack buffer**. The function writes 8 fields (4 bytes each) into it before the memcpy, consuming **32 bytes**. This leaves only **96 bytes** remaining on the stack buffer.

The `memcpy()` at the bottom copies `oa->oa_length` bytes from `oa->oa_base` into `buf` (pointing just past the 32-byte header within `rpchdr`). **There is no bounds check** on `oa->oa_length` against the remaining space in `rpchdr`.

### Why it is exploitable

| Factor | Detail |
|--------|--------|
| **Buffer size** | 128 bytes total, 96 bytes available after header |
| **Source** | `oa->oa_base` — pointer from the network packet |
| **Length** | `oa->oa_length` — field from the network packet |
| **Check** | None — only an empty guard (`if (oa->oa_length)`) |
| **Context** | Kernel space (`svc_` prefix = service handler) |

The `msg` structure is populated from an incoming network packet. Both `oa_base` (a pointer) and `oa_length` (an integer) are parsed from the RPC credential. An attacker controlling both values can:

1. Set `oa_length` to a large value (e.g., 0x100 = 256) to guarantee overflow beyond the 128-byte stack buffer.
2. Set `oa_base` to an attacker-controlled buffer containing crafted data, such as a ROP chain or shellcode.

### Attack scenario

```
Attacker (unauthenticated, over network)
       |
       |  Crafted RPCSEC_GSS RPC request (e.g., NFS mount/query)
       |  - oa_flavor = RPCSEC_GSS
       |  - oa_length = 200+ bytes  (exceeds 96-byte remaining space)
       |  - oa_base  = pointer to attacker's buffer
       |
       v
NFS server kernel                                   
svc_rpc_gss_validate()                              
  rpchdr overflow  <================================
  stack cookie/gs                                  
  saved return PC overwritten                      
  attacker controls RIP                            
  kernel shellcode executes                        
```

### Impact

- **Confidentiality:** Full kernel memory exposure
- **Integrity:** Arbitrary kernel code execution
- **Availability:** Kernel panic / system crash
- **Scope:** Complete system compromise — the vulnerability exists in kernel space with full privileges

Since this is triggered from a network-received RPC request, **no authentication is required** to trigger it.

## Note on MAX_AUTH_BYTES

`MAX_AUTH_BYTES` (400) is defined elsewhere in the RPC subsystem but is **not consulted** in this function. Even if it were, 400 bytes far exceeds the 96 bytes available in `rpchdr` after the header, so simply enforcing that limit would still leave an overflow path. The fix must check against the **remaining space in the local buffer**, not an external credential size limit.

## Mitigation

Add a bounds check before the `memcpy()`:

```c
size_t remaining = sizeof(rpchdr) - ((uintptr_t)buf - (uintptr_t)rpchdr);
if (oa->oa_length > remaining)
    return (FALSE);  /* reject — credential too large for signature buffer */
```

## References

- CWE-121: Stack-based Buffer Overflow
- CWE-20: Improper Input Validation
- CVE-2025-48304 (if applicable — same class of bug in this subsystem)
