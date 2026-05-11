# Overcoming Limited Overflow Space for Kernel Exploitation

## Problem Statement
The stack overflow provides **~304 bytes of controlled data past the header**, equivalent to roughly **38 ROP gadgets** (assuming 8‑byte pointers). A full exploit chain to write an SSH key to disk via `kern_openat` and `kern_writev` — including setting up `iovec`/`uio` structures in kernel memory — requires far more than 38 gadgets (≈1000+ bytes). This appears insufficient for a direct ROP chain.

## Solution: Stack Pivoting to User‑Space Memory

### Core Idea
Instead of placing the entire ROP chain in the limited stack overflow region, use the overflow to **pivot the kernel stack pointer (RSP) to a user‑space buffer** that contains the full, complex ROP chain.

### Why This Works
1. **SMEP** prevents the kernel from executing user‑space **code**, but it does not prevent the kernel from reading user‑space **data**.
2. A ROP chain consists of kernel‑text addresses (gadgets) stored as data pointers. These pointers can reside in user‑space memory; the CPU fetches instructions from kernel‑text addresses, not from the user‑space buffer itself.
3. By moving RSP to a user‑space address, we can supply an arbitrarily long ROP chain limited only by available user‑space memory.

### Technique
1. **Overwrite saved RBP** on the stack with a **controlled value** pointing to user‑space memory.
2. Use a **stack‑pivot gadget** (e.g., `mov rsp, rbp ; pop rbp ; ret`) to load RSP from the corrupted RBP.
3. The user‑space buffer contains:
   - A **large ROP chain** implementing the full exploit (disable SMEP, elevate privileges, call `kern_openat`/`kern_writev`, etc.).
   - Necessary kernel data structures (`iovec`, `uio`) constructed via ROP‑driven writes.

### Implementation Steps
1. **Craft the overflow payload** (within the ~304 bytes):
   - Padding to reach saved RBP.
   - Value for RBP: address of user‑space buffer (mapped via `mmap`).
   - Return address: address of stack‑pivot gadget.
2. **User‑space buffer layout** (mapped as readable/writable):
   - **Stage‑1 ROP chain** (immediately after RBP):
     - Disable SMEP (clear CR4 bit 20).
     - Elevate privileges (`commit_creds(prepare_kernel_cred(0))`‑style).
     - Copy larger stage‑2 payload into kernel memory via `copyin`.
     - Jump to stage‑2.
   - **Stage‑2 payload** (arbitrary size):
     - Full `kern_openat`/`kern_writev` chain.
     - In‑memory `iovec`/`uio` structures built via ROP‑controlled writes.
3. **Ensure alignment**: The user‑space buffer must be page‑aligned and marked readable (no execute required).

### Advantages
- **Unlimited chain length** – user‑space memory can hold megabytes of ROP gadgets.
- **Flexibility** – complex data structures can be constructed incrementally.
- **Reusability** – the same pivot technique works for many kernel exploits.

### Challenges & Mitigations
1. **Finding a stack‑pivot gadget** – need `mov rsp, rbp` or equivalent (`xchg rsp, rbp`, `lea rsp, [rbp+...]`). In FreeBSD kernel, such gadgets exist (common in function epilogues).
2. **Ensuring user‑space buffer is mapped** – exploit must call `mmap` before triggering overflow.
3. **Avoiding NULL bytes** – kernel addresses may contain NULL bytes; use gadgets that avoid string operations.
4. **Preserving register state** – after pivot, registers may contain attacker‑controlled values; choose gadgets that pop needed values from the new stack.

## Alternative: Multi‑Stage ROP with `copyin`
If a stack‑pivot gadget is unavailable, a minimal ROP chain within the 304 bytes can:
1. Disable SMEP.
2. Call `copyin(src_user, dst_kernel, large_len)` to copy a larger stage‑2 payload into a known kernel address (e.g., unused region of kernel heap).
3. Jump to the copied payload.

This requires:
- Gadgets to set RDI (src), RSI (dst), RDX (len).
- Address of `copyin`.
- A writable kernel address (maybe obtained via `alloc` or known static buffer).

## Data‑Only Attack
If the goal is merely privilege escalation (not file writing), a **data‑only attack** may suffice:
- Overwrite `struct ucred` of the current process (reachable via `curthread->td_proc->p_ucred`).
- Set `cr_uid`, `cr_ruid`, etc., to 0.
- This can be done with fewer gadgets, possibly within 304 bytes.

## Summary
The limited overflow space is not a fundamental barrier. **Stack pivoting** to user‑space memory allows an arbitrarily large ROP chain. With no KASLR, the attacker knows the exact addresses of pivot gadgets and kernel functions, making the technique reliable.