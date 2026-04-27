# Case 3: Bounds Check Analysis — Partial Fix with Residual Vulnerability

## Verdict: Bounds Check is Correct for `rpchdr`, but Verifier Length is Unchecked

The bounds check on `oa->oa_length` correctly fixes the stack buffer overflow from cases 1 and 2. **However, the function still contains a vulnerability** — `msg->rm_call.cb_verf.oa_length` is used without any bounds check.

## Analysis of the Bounds Check

```c
if (oa->oa_length > sizeof(rpchdr) - 8 * BYTES_PER_XDR_UNIT) {
    client->cl_state = CLIENT_STALE;
    return (FALSE);
}
```

| Parameter | Value |
|-----------|-------|
| `sizeof(rpchdr)` | 128 bytes |
| `8 * BYTES_PER_XDR_UNIT` | 32 bytes (8 fields x 4 bytes) |
| Maximum allowed `oa->oa_length` | 96 bytes |

After the 32-byte header, `rpchdr` has exactly 96 bytes remaining. The `memcpy` copies precisely `oa->oa_length` bytes. When `oa->oa_length` = 96 (the maximum allowed), the `memcpy` writes exactly to the last byte of `rpchdr` — no overflow.

Tracing through `buf` arithmetic:

```
buf = rpchdr + 8;           // after 8 IXDR_PUT calls
memcpy(buf, oa->oa_base, 96);  // copies bytes [8..31] of rpchdr
buf += RNDUP(96) / 4;       // buf = rpchdr + 32 (one past end, valid in C)
```

Then `rpcbuf.length = (u_char *)buf - (u_char *)rpchdr = 128`, which is correct — 32 bytes of header + 96 bytes of credential.

**The bounds check is sound.** The original stack buffer overflow vulnerability is fixed.

## Residual Vulnerability: Unchecked Verifier Length

```c
checksum.value = msg->rm_call.cb_verf.oa_base;
checksum.length = msg->rm_call.cb_verf.oa_length;

maj_stat = gss_verify_mic(&min_stat, client->cl_ctx, &rpcbuf, &checksum,
              &qop_state);
```

`oa->oa_length` (the credential length) is now bounds-checked. But `msg->rm_call.cb_verf.oa_length` (the **verifier** length) has **no validation whatsoever**. In RPCSEC_GSS, the verifier contains the GSS signature MIC that the server sends back to the client — both `oa_base` and `oa_length` are parsed from the incoming network packet.

If `oa_length` exceeds the actual size of the verifier buffer in the mbuf, `gss_verify_mic` will read beyond the allocated buffer into adjacent kernel memory. This is an **out-of-bounds read** in kernel context.

### Why This Matters

The GSS mechanism's `gss_verify_mic` implementation reads `checksum.length` bytes from `checksum.value`. If the verifier's `oa_length` is inflated (e.g., set to 0x10000 while the actual buffer is only 128 bytes), the GSS layer reads that many bytes from `oa_base`, spanning into unrelated kernel memory.

### Inconsistency Between Credential and Verifier Handling

| Field | Bounds Checked | Safe |
|-------|---------------|------|
| `msg->rm_call.cb_cred.oa_length` | Yes | Yes |
| `msg->rm_call.cb_verf.oa_length` | **No** | **No** |

The fix addressed the credential length but ignored the verifier length, creating an asymmetry where one path is protected and the other is not.

### Exploitation

An attacker sends a crafted RPCSEC_GSS request with:

- `cb_cred.oa_length` within the allowed 96-byte limit (passes the bounds check)
- `cb_verf.oa_length` inflated far beyond the actual verifier buffer size
- `cb_verf.oa_base` pointing to a kernel data structure of interest

`gss_verify_mic` then reads attacker-controlled amount of data from `oa_base`, leaking kernel memory contents to the attacker through the GSS response or error messages.

### Severity

| Factor | Value |
|--------|-------|
| Impact | Kernel memory disclosure (KASLR bypass if enabled, secret extraction) |
| Access vector | Network, port 2049/TCP |
| Authentication | Not required to trigger |
| CVSS base | High (network, no auth, memory leak) |

Note: The actual exploitability depends on whether the GSS mechanism's `gss_verify_mic` implementation itself performs internal bounds checking. In practice, many GSS mechanisms (especially Kerberos-based ones) trust the length parameter, making this exploitable.

## Summary

The bounds check correctly fixes the stack buffer overflow, but the function still passes unchecked attacker-controlled values to `gss_verify_mic` via the verifier. This is a **separate, independent vulnerability** — an out-of-bounds read in kernel context — that was not addressed by the fix.
