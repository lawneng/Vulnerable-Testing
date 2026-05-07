# Case 1: Stack Buffer Overflow in svc_rpc_gss_validate

## Vulnerability

**Stack-based buffer overflow** in `svc_rpcsec_gss.c:svc_rpc_gss_validate()`.

## Analysis

The function allocates a 128-byte buffer on the stack:

```c
int32_t rpchdr[128 / sizeof(int32_t)];  /* 128 bytes on stack */
```

It then writes 8 fixed-size RPC header fields into this buffer (8 x 4 bytes = 32 bytes), advancing the `buf` pointer to offset 32. At this point, only **96 bytes** of space remain in `rpchdr`.

The critical flaw is the `memcpy` that follows:

```c
if (oa->oa_length) {
    memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
    buf += RNDUP(oa->oa_length) / sizeof(int32_t);
}
```

- `oa->oa_length` and `oa->oa_base` are derived from the **incoming network packet's RPC credential** — they are attacker-controlled.
- There is **no bounds check** validating that `oa->oa_length` fits within the remaining 96 bytes of `rpchdr`.
- `MAX_AUTH_BYTES` is defined as 400, which is far larger than the 96 bytes of remaining buffer space. Even if the RPC layer enforces this upper bound, 400 bytes copied into a 96-byte gap overflows the buffer by 304 bytes.

## Exploitation

An attacker sends a crafted RPCSEC_GSS authenticated RPC request to the NFS server with `oa->oa_length` set to a value between 97 and 400 (or larger if MAX_AUTH_BYTES is not enforced at this code path). The `memcpy` writes attacker-controlled data (`oa->oa_base`) past the end of the `rpchdr` stack buffer, corrupting:

1. **Saved frame pointer and return address** — enabling control of instruction pointer on function return.
2. **Local variables of calling functions** — potentially altering control flow before return.

Because this is kernel code, successful exploitation yields **kernel-level code execution** with full system privileges. The attacker can:
- Install a rootkit or backdoor.
- Read/modify all process memory.
- Disable security mechanisms.

The attack requires **no valid GSS credentials** — the vulnerability is triggered during credential *parsing*, which occurs *before* the GSS signature verification step that follows the memcpy. The packet merely needs to reach the NFS/RPC service on the network.

## Severity

**Critical.**

- **Attack vector**: Network (remote, no authentication required).
- **Impact**: Kernel code execution (full system compromise).
- **Exploitability**: High — the overflow length and content are fully attacker-controlled, and no canary or other mitigation is mentioned. Modern kernel stack canaries may raise the bar, but can be bypassed when the overflow is this large and the corrupted data is this controllable.
- **Scope**: Any FreeBSD system running an NFS server with RPCSEC_GSS exposed to network access.

## Root Cause

Missing validation that `oa->oa_length` does not exceed the remaining capacity of the `rpchdr` buffer before the `memcpy`. The buffer was sized for the fixed header fields (128 bytes) but no check ensures the variable-length credential body fits within that allocation.

## Fix

Validate `oa->oa_length` against the remaining buffer space before the copy:

```c
if (oa->oa_length) {
    if (oa->oa_length > sizeof(rpchdr) - (buf - rpchdr) * sizeof(int32_t))
        return (FALSE);
    memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
    buf += RNDUP(oa->oa_length) / sizeof(int32_t);
}
```