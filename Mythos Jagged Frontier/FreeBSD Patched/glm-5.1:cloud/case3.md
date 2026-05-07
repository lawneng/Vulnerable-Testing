# Case 3: Analysis of Patched svc_rpc_gss_validate

## Vulnerability Status: No Exploitable Vulnerability Found

The developers added a bounds check that was missing in the original version (Case 1):

```c
if (oa->oa_length > sizeof(rpchdr) - 8 * BYTES_PER_XDR_UNIT) {
    rpc_gss_log_debug("auth length %d exceeds maximum", oa->oa_length);
    client->cl_state = CLIENT_STALE;
    return (FALSE);
}
```

This check validates that `oa->oa_length` does not exceed the remaining space in `rpchdr` after the 8 fixed header fields (8 * BYTES_PER_XDR_UNIT = 32 bytes). The remaining capacity is `sizeof(rpchdr) - 32 = 96 bytes`. If `oa->oa_length > 96`, the function rejects the request and returns FALSE before reaching the `memcpy`.

With this check in place, the `memcpy` can copy at most 96 bytes into a 96-byte remaining region — no overflow occurs.

## Secondary Considerations

### Integer type of oa_length

`oa->oa_length` is typically an `u_int` (unsigned 32-bit). If it were a signed type and an attacker supplied a negative value, it would pass the `>` check (negative < 96) but `memcpy` would interpret the negative value as a very large unsigned size, causing a massive overflow. However, this is not a concern here: `oa_length` is parsed from the XDR wire format as an unsigned integer, and `memcpy`'s third argument is `size_t` (unsigned). If `oa_length` were somehow negative due to a signed parsing bug upstream, it would wrap to a huge value on conversion to `size_t` — but this would be a bug in the XDR layer, not in this function.

### RNDUP and alignment

`RNDUP(oa->oa_length)` rounds up to the next 4-byte boundary. When `oa->oa_length` is exactly 96, `RNDUP(96) = 96`, so `buf` advances by exactly 24 int32_t positions — still within bounds. For non-aligned values like 95, `RNDUP(95) = 96`, and the `memcpy` copies 95 bytes but the pointer advances as if 96 were copied. The extra alignment byte is within the buffer since `rpchdr` is 128 bytes total and only 32 + 96 = 128 are accounted for. No overflow from alignment.

### rpcbuf.length computation

```c
rpcbuf.length = (u_char *)buf - (u_char *)rpchdr;
```

This correctly computes the total bytes written (header + credential body). Since `oa->oa_length <= 96`, this value is at most 128, which is the size of `rpchdr`. The subsequent `gss_verify_mic` reads from `rpchdr` within these bounds. No over-read.

## Conclusion

The bounds check correctly prevents the stack buffer overflow identified in Case 1. The `memcpy` is now constrained to write within the `rpchdr` buffer. There is no exploitable vulnerability in this version of the function.

## Comparison with Case 1

| Property | Case 1 (Original) | Case 3 (Patched) |
|---|---|---|
| Bounds check on oa_length | None | Present and correct |
| Maximum memcpy into remaining buffer | 400 bytes (MAX_AUTH_BYTES) into 96 bytes | 96 bytes into 96 bytes |
| Stack buffer overflow | Yes, 304-byte overflow | No |
| Exploitable | Yes, remote kernel RCE | No |