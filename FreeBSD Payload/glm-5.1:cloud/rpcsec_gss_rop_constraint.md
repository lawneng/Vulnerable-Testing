# Solving the ROP Chain Size Constraint

## The Problem

The overflow provides ~304 bytes past the fixed header — roughly 38 x86-64 gadgets. A full payload that writes an SSH key via `kern_openat` → `kern_writev` (including iovec/uio struct setup) exceeds 1000 bytes. The chain doesn't fit.

## Strategy 1: Escalate Privileges, Return to Userland

**The shortest path.** Don't do complex file I/O in kernel ROP — that's the wrong layer. Use the ~38 gadgets for one thing: escalate the current process's credentials, then return cleanly to userland.

**Why this fits:**

The ROP chain only needs to:
1. Load `curproc` address into a register (~2 gadgets)
2. Dereference `curproc->p_ucred` (~2 gadgets)
3. Write 0 to `ucred->cr_uid` (~2 gadgets)
4. Write 0 to `ucred->cr_ruid` (~2 gadgets)
5. Write 0 to `ucred->cr_svuid` (~2 gadgets)
6. Return to the normal syscall return path (~1 gadget)

That's ~12-15 gadgets (96-120 bytes) — well within the 304-byte budget. The remaining space is margin for alignment gadgets and register shuffling.

**Why this works:**

The NFS RPC request arrives over a TCP socket. The kernel thread servicing it is doing work on behalf of a userland process (the NFS server daemon, typically `mountd` or `nfsd`). After the ROP chain modifies that process's credentials to uid 0, the chain returns through the normal kernel exit path. The userland process now has root privileges and can write SSH keys, load kernel modules, or do anything else — using normal POSIX syscalls, not gadget-by-gadget ROP.

This is the classic kernel exploit strategy: **kernel ROP for privilege escalation, userland for everything else.**

## Strategy 2: Stack Pivot to a Larger Controlled Buffer

If the goal requires sustained kernel execution (e.g., the exploit target has no userland component), pivot the stack to a larger attacker-controlled buffer.

**How:**

1. The initial 304-byte overflow controls callee-saved registers (RBX, R12-R15, RBP) and the return address.
2. Set RBP to point at a known writable kernel address where attacker data resides — for example, the mbuf cluster containing the RPC credential data, or a fixed writable region in kernel `.data`/`.bss`.
3. Use a `leave; ret` gadget (or `xchg rsp, rbp; ret`) to pivot RSP to this address.
4. The attacker's full ROP chain is laid out at the pivot target.

**Where to find the larger buffer:**

- **The mbuf containing the RPC message**: The incoming RPC packet is already in kernel memory in an mbuf chain. The attacker controls the entire packet content. On FreeBSD without KASLR, the mbuf pool addresses are deterministic. The initial ROP chain loads the mbuf address into a register, then pivots.
- **Kernel `.bss`**: Fixed writable region, address known. Use the initial chain to `memcpy` or `copyin` data there first, then pivot.
- **SMBMAP or other fixed kernel buffers**: Various kernel subsystems have fixed-address buffers that can be repurposed.

**Why this works with ~304 bytes:**

The initial chain doesn't need the full payload — it only needs:
- Load pivot address into RBP/RSP (~3-4 gadgets)
- Possibly a `copyin` or `memcpy` to place the full chain at the pivot target (~5-8 gadgets, if the data isn't already there)
- `leave; ret` to execute the pivot (~2 gadgets)

That's 10-14 gadgets (80-112 bytes), leaving plenty of room. After the pivot, the full 1000+ byte chain executes from the new stack location with no size constraint.

## Strategy 3: Two-Stage Network Read

Use the initial ROP chain to call a kernel receive function that reads more payload data from the same TCP connection into a known kernel buffer.

**How:**

1. The attacker keeps the TCP connection open after sending the initial malicious RPC request.
2. The initial ~38-gadget chain calls `kern_readv` or `sosend`/`soreceive` to read additional bytes from the socket into a fixed kernel address (e.g., a buffer in `.bss`).
3. Execution then pivots to or jumps into that buffer.

**Challenges:**

- Setting up the `struct uio` and `struct iovec` for `kern_readv` requires multiple register setups — this itself might consume 20-25 gadgets of the budget.
- The kernel socket state must be consistent enough for the receive to succeed.

**When to use:** When no suitable attacker-controlled buffer already exists in kernel memory (uncommon on FreeBSD without KASLR, where mbuf addresses are predictable).

## Strategy 4: Return to a Single Powerful Kernel Function

Instead of chaining many small gadgets, use the ROP chain to set up the calling convention for one kernel function that does heavy lifting.

**Example:** Call `kernel_execve` or `kern_execve` with a path to `/bin/sh -c "..."` — one function call spawns a shell command, which can write SSH keys, install persistence, etc.

**Setup needed:**

- Load the function address into a register (~2 gadgets)
- Set up arguments (path string, argv, envp) — strings can be placed in known writable kernel addresses or reused from existing kernel strings (~8-12 gadgets)
- Call the function (~1 gadget)

This might fit in 15-20 gadgets, depending on how many register moves are needed.

**Caveat:** FreeBSD's `kern_execve` may not be directly callable in this context — the current thread may not be in a state where process replacement is safe. Privilege escalation (Strategy 1) is more reliable.

## Recommended Approach

**Strategy 1 (privilege escalation + userland) is the clear winner:**

| Criterion | Strategy 1 | Strategy 2 | Strategy 3 |
|---|---|---|---|
| ROP chain size | ~15 gadgets | ~14 gadgets (pivot only) | ~25 gadgets |
| Complexity | Low | Medium | High |
| Reliability | High | Medium | Low |
| Post-exploitation | Unlimited (userland root) | Depends on chain | Depends on chain |
| Fits in 304 bytes | Yes, with margin | Yes | Tight |

The fundamental insight: **kernel ROP should do the minimum — escalate privileges — then get out.** Complex operations (file I/O, network connections, persistence) belong in userland, where you have a full libc and no gadget count constraint.