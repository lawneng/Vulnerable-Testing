# Exploitation Strategy: Limited Buffer Overflow Space

## The Constraint

- **Available overflow:** ~304 bytes (38 int32_t units)
- **Required payload:** 1000+ bytes for full ROP chain (kern_openat + kern_writev with iovec/uio setup)
- **Gap:** ~700 bytes short

## Solution: Staged Stack Pivot to Controlled Buffer

The key insight: while the stack overflow is limited, the attacker **controls the RPC packet content**, which can be arbitrarily large (up to NFS packet size limits, typically several KB).

### Step 1: Locate the RPC Packet Buffer

The incoming RPC request is stored in kernel memory before `svc_rpc_gss_validate()` is called. On FreeBSD without KASLR, this buffer has a predictable location relative to the socket buffer (mbuf) or can be referenced via function arguments that remain in registers/stack.

### Step 2: Minimal First-Stage ROP (≤304 bytes)

Use the overflow to execute a **stack pivot** that transfers execution to the attacker-controlled RPC packet buffer:

```
Stage 1 ROP chain (in 304-byte overflow):
  1. pop rax ; ret                    [8 bytes]
     0xfffff80012345678               [8 bytes]  # RPC packet buffer address
  2. mov rsp, rax ; ret                 [8 bytes]  # Stack pivot
```

Or using a traditional leave/ret pivot:
```
  1. pop rbp ; ret                    [8 bytes]
     0xfffff80012345600               [8 bytes]  # RPC buffer - 8
  2. leave ; ret                      [8 bytes]   # mov rsp, rbp ; pop rbp ; ret
```

### Step 3: Second-Stage ROP Chain (in RPC Packet Body)

The RPC packet body (after the credential header) contains the full 1000+ byte ROP chain with:

1. **Setup Phase:**
   - Find current thread structure (from %gs or %fs base)
   - Locate process credentials
   - Allocate kernel memory for file path and SSH key content

2. **File Operations:**
   - Call `kern_openat()` with path `/etc/ssh/authorized_keys`
   - Call `kern_writev()` with iovec pointing to embedded SSH key
   - Call `kern_close()`

3. **Cleanup:**
   - Restore stack to legitimate state
   - Return from `svc_rpc_gss_validate()` normally
   - Exploit succeeds silently

### Step 4: Addressing the "Where to Pivot"

**Option A: Socket Buffer Address in Registers**

When the NFS worker thread calls `svc_rpc_gss_validate()`, the `msg` parameter points to the parsed RPC message structure. If we can locate the original packet buffer from `msg` or preserved registers (R12-R15 which we control in the overflow), we calculate the offset to the packet body where we embedded our ROP chain.

**Option B: Stack Address Calculation**

Use the overflow to read RSP (via side channels or known offsets), then calculate the RPC buffer address based on known kernel memory layout (no KASLR means fixed offsets between kernel data regions).

**Option C: Register Preservation**

The overflow overwrites saved registers (RBX, R12-R15). Before pivoting, these registers might contain useful pointers. We can craft values such that:
- One register points to our RPC buffer
- Another points to useful kernel data structures

Then use a "mov rsp, [reg]" or similar gadget to pivot.

## Alternative: Call Existing Kernel Functions

Instead of a 1000-byte ROP chain, use the limited 304 bytes to call a single high-level kernel function that does the heavy lifting:

### Approach: Direct System Call from Kernel

FreeBSD allows calling system calls from kernel context via `sysent[]` table:

```c
// In 304-byte overflow:
1. Set up args for open() syscall
2. Call sys_open via syscall instruction or direct call
3. Set up args for write()  
4. Call sys_write
5. Set up args for close()
6. Call sys_close
7. Return
```

This reduces the gadget count significantly—instead of building complex iovec structures manually, let the syscall handlers do it.

### Approach: Use VFS Helper Functions

Call higher-level VFS functions directly:
```
vn_open()      # Open vnode directly
vn_write()     # Write to vnode
vn_close()     # Close vnode
```

These take simpler arguments than kern_writev() and require fewer setup gadgets.

## The Practical Exploit Flow

```
Attacker RPC Packet:
+----------------------------------+
| RPC Header (credential)          |
|   - oa_length = 304 (crafted)    |
|   - Overflow payload (304 bytes): |
|     [Stack pivot to packet body]  |
+----------------------------------+
| RPC Body (arbitrary size):         |
|   [NOP sled]                      |
|   [Full 1000-byte ROP chain]      |
|   [SSH key data]                  |
+----------------------------------+

Execution:
1. memcpy copies 304 bytes → overflows, overwrites return addr
2. Return executes stack pivot → jumps to RPC body
3. Full ROP chain executes from RPC body
4. SSH key written to disk
5. Clean return
```

## Key Challenges and Mitigations

| Challenge | Solution |
|-----------|----------|
| **Finding RPC buffer address** | No KASLR means fixed offsets; or use register that still points to socket buffer |
| **Stack alignment (x86_64 requires 16-byte)** | Include alignment gadgets in first stage |
| **SMEP/SMAP** | All execution in kernel space, no user memory access needed |
| **Packet size limits** | NFS typically allows 8KB+ UDP or TCP streams; plenty of space |

## Conclusion

The limited ~304 byte overflow is **not a barrier** to exploitation because:

1. The RPC packet body provides an arbitrarily large attacker-controlled buffer
2. A simple stack pivot (8-24 bytes of ROP) transfers execution to that buffer
3. The full payload executes from the packet body with no size constraints

This is a standard kernel exploitation technique: **overflow for control, pivot for payload**.

**Success outcome:** Remote unauthenticated attacker achieves kernel code execution and writes arbitrary files (SSH keys, backdoors) to the filesystem.
