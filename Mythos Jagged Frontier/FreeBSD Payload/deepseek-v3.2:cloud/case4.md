# Overcoming Space Constraints: Exploiting with Limited ROP Gadgets

## Problem Statement

The stack overflow provides ~304 bytes of controlled data past the buffer end, equating to roughly **38 ROP gadgets** (assuming 8‑byte gadgets on 64‑bit). A full chain to write an SSH key to disk via `kern_openat` and `kern_writev` requires **over 1000 bytes** (>125 gadgets) — far exceeding the available space.

## Core Challenge

Directly embedding a complete file‑writing ROP chain is impossible within the overflow region. We need techniques to **amplify control** using the limited initial overflow.

## Solution Strategies

### 1. Multi‑Stage ROP (Staged Payload)

**Idea**: Use the initial overflow to execute a small first‑stage chain that copies a larger second‑stage payload into kernel‑accessible memory, then jumps to it.

**Implementation**:

1. **Locate a suitable kernel buffer**:
   - The NFS packet itself resides in kernel memory (mbuf chain).
   - The `oa_base` pointer points into the received packet data.
   - Additional data could be placed **after** the credential field in the same packet.

2. **First‑stage chain (≤38 gadgets)**:
   - Compute address of second‑stage payload within the mbuf.
   - Copy payload from mbuf to a safe kernel region (e.g., via `bcopy`).
   - Jump to the copied payload.

3. **Second‑stage payload**:
   - Contains the full 1000+‑byte ROP chain for file operations.
   - Stored **after** the `oa_base` data in the same packet.
   - Accessed via pointer arithmetic: `second_stage = oa_base + oa_length`.

**Advantages**:
- Leverages existing kernel buffer (mbuf) for storage.
- First‑stage chain is minimal (copy + jump).
- Second‑stage can be arbitrarily large.

**Challenges**:
- Must ensure second‑stage data survives packet processing.
- Need to locate mbuf metadata to compute its base address.

### 2. Heap‑Oriented Primitive

**Idea**: Use the overflow to corrupt adjacent kernel‑heap objects, turning the limited overflow into a more powerful primitive (e.g., arbitrary write).

**Implementation**:

1. **Target a useful kernel object**:
   - The `client` pointer (`struct svc_rpc_gss_client`) is passed as first argument.
   - Overflow could overwrite fields in this structure or adjacent heap objects.

2. **Achieve arbitrary write**:
   - Overwrite a function pointer in `client` or related structure.
   - Overwrite a length field to create a heap‑overflow later.
   - Overwrite a pointer to gain arbitrary read/write.

3. **Chain to file operations**:
   - With arbitrary write, patch kernel code or data to disable SMAP/SMEP.
   - Overwrite a system‑call handler to execute custom code.
   - Modify current thread’s `ucred` to gain root privileges, then return to userland and spawn a shell.

**Advantages**:
- Can achieve powerful primitives with few gadgets.
- Doesn’t require copying large payloads.

**Challenges**:
- Requires knowledge of heap layout (non‑deterministic).
- May need heap‑spraying to increase reliability.

### 3. Code‑Reuse via Existing Kernel Functions

**Idea**: Locate a kernel function that already performs the desired file operations (or can be tricked into doing so) and call it directly.

**Implementation**:

1. **Find a suitable kernel function**:
   - `kern_openat` / `kern_writev` are obvious but require many arguments.
   - Simpler functions: `kexec` (load new kernel), `sysctl` (modify kernel state), `kldload` (load kernel module).
   - Could load a malicious kernel module that provides root access.

2. **Argument preparation**:
   - Place arguments in registers/stack via limited ROP.
   - Use `oa_base` region as a data area for strings (e.g., `/tmp/authorized_keys`).

3. **SMAP bypass**:
   - If SMAP is enabled, kernel cannot dereference user‑space pointers.
   - Need to place string data in kernel‑accessible memory (e.g., mbuf).

**Example chain** (simplified):
```
pop rdi; /tmp/authorized_keys string address
pop rsi; O_WRONLY|O_CREAT
pop rdx; 0600
call kern_openat
mov rbx, rax        ; save fd
pop rdi, rsi, ...   ; setup writev arguments
call kern_writev
pop rdi, rbx        ; restore fd
call kern_close
```

**Challenges**:
- Still requires ~10–15 gadgets just for open/write/close.
- May exceed 38‑gadget budget if SMAP/SMEP disabling is needed.

### 4. Data‑Only Attack (Privilege Escalation)

**Idea**: Forget file writing; instead, modify the current thread’s credential structure to gain root privileges, then return to userland.

**Implementation**:

1. **Locate `struct ucred`**:
   - Kernel stores per‑thread credentials.
   - Can be found via `curthread->td_ucred` or `curproc->p_ucred`.

2. **Overwrite credential fields**:
   - `cr_uid = 0`
   - `cr_ruid = 0`
   - `cr_svuid = 0`
   - Similarly for groups.

3. **Return to userland**:
   - Restore stack and registers.
   - `iretq` back to user‑mode shellcode.

**Advantages**:
- Requires very few gadgets (maybe 5‑10).
- Simpler than file operations.
- Immediately gives root privileges.

**Challenges**:
- Need to find `curthread` or `curproc` pointer.
- Must preserve kernel stack integrity to avoid panic.

### 5. Stack Pivoting

**Idea**: Use the overflow to change the stack pointer (`RSP`) to a larger attacker‑controlled buffer, then continue execution there.

**Implementation**:

1. **Identify a suitable destination**:
   - The mbuf chain containing the packet data.
   - A kernel heap allocation under attacker control.

2. **Pivot stack**:
   - Gadget: `mov rsp, rax` (or `xchg rsp, rax`).
   - Load destination address into `rax`.
   - Pivot; new stack contains full ROP chain.

3. **Execute large chain**:
   - Destination buffer holds 1000+ bytes of ROP gadgets.
   - Can perform complex file operations.

**Advantages**:
- Overcomes space limitation completely.
- Allows arbitrary‑length ROP chain.

**Challenges**:
- Need a controllable kernel memory region with known address.
- Must preserve stack alignment.

## Recommended Approach

Given FreeBSD 14.x **without KASLR**:

1. **First‑stage**: Use ≤38 gadgets to:
   - Disable SMAP/SMEP (if enabled) by writing to `CR4`.
   - Locate the mbuf containing our packet (`oa_base` points into it).
   - Compute address of second‑stage payload placed after `oa_base`.
   - Copy second‑stage to executable kernel memory (or use stack pivot).

2. **Second‑stage**: Full ROP chain to:
   - Elevate privileges via `ucred` modification.
   - Write SSH key using `kern_openat`/`kern_writev`.
   - Clean up and return safely.

3. **Alternative**: If SMAP is disabled, place file‑path strings and payload in user‑space memory and reference them directly.

## Conclusion

The 304‑byte overflow is sufficient for exploitation despite the 1000+‑byte requirement. The key is to use the initial overflow to **bootstrap a larger payload** via multi‑stage execution, heap corruption, or stack pivoting. Without KASLR, fixed kernel addresses make these techniques feasible.