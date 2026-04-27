# Case 4: Overflow Size vs. Payload Size — The Core Exploitation Problem

## The Problem

| Metric | Value |
|--------|------|
| Stack overflow size | ~304 bytes |
| Gadget capacity (8 bytes/gadget) | ~38 gadgets |
| Payload needed for SSH key write (kern_openat + kern_writev + struct setup) | 1000+ bytes |
| Shortfall | ~26x |

The 304 bytes of controlled data on the stack can hold ~38 ROP gadgets. A complete payload — setting up a `uio` struct, setting up an `iovec` array, calling `kern_openat` to open `/root/.ssh/authorized_keys`, calling `kern_writev` with the key data, and closing the fd — requires over 1000 bytes of ROP code. The overflow simply cannot hold the full chain inline.

## Why This Is Hard

The payload must:

1. **Set up a `uio` struct** in kernel-accessible memory (uio_resid, uio_iov, uio_iovcnt, uio_segflg, uio_rw, uio_td) — 64+ bytes of struct
2. **Set up an `iovec` array** — the write data pointer, length, and the actual data (SSH key) — 64+ bytes
3. **Open the file** — call `kern_openat` with proper fd, path, flags (at least 3 arguments, each needing `mov`/`lea`/`syscall` sequences)
4. **Write the file** — call `kern_writev` with uio pointer (at least 2 arguments)
5. **Close the fd** — call `__sys_close`
6. **Return cleanly** — exit through the RPC layer without panicking

Each operation needs multiple ROP gadgets (pop arguments, setup registers, indirect calls). 38 gadgets at 8 bytes each simply cannot express all of this.

## Solutions

### Solution A: Jump to the Mbuf Payload (Recommended)

**Core insight:** The 304 bytes of overflow data comes from `memcpy(buf, oa->oa_base, oa->oa_length)`, where `oa_base` points into the mbuf chain. The attacker's network buffer is much larger than 304 bytes. The overflow payload **is stored in the mbuf chain**.

**Technique:** Use the 304-byte stack overflow to establish a small ROP chain that jumps into the mbuf chain, which contains the larger payload.

#### Step 1: Stack Overflow Data Layout

```
Offset 0-303:   304 bytes of controlled stack data
  [0..31]:       8 IXDR header values (overwrite with saved callee-saved registers)
  [32..47]:      filler / saved RBP overwrite
  [48..55]:      return address R0 (points to a small ROP "loader" gadget)
  [56..303]:     NOT USED (stack beyond overflow — normal stack data)

Buffer ends at offset ~55. Mbuf chain continues beyond.
```

#### Step 2: Mbuf Chain Layout (Beyond the Overflow Copy)

The attacker's mbuf chain is sent over the network. The `memcpy` copies only 304 bytes into the stack, but the **rest of the mbuf chain remains intact in kernel memory**. The attacker places the full ROP payload there:

```
Mbuf chain:
  [0..303]:     overflow data (copied to stack)
  [304..311]:   "JUMP HERE" — return address pointing here
  [312..1311]:  FULL ROP PAYLOAD (1000 bytes)
    [312..]:    setup uio struct in known mbuf region
    [..]:       setup iovec array in known mbuf region
    [..]:       call kern_openat
    [..]:       call kern_writev
    [..]:       call __sys_close
    [..]:       ret to safe cleanup function
  [1312+]:      padding / clean exit data
```

#### Step 3: The Jump — Returning to Mbuf Data

The challenge: the stack and the mbuf are in **different memory regions**. The stack address is `rsp - offset_in_frame`, and the mbuf address is `oa_base`. We need a gadget that can compute `oa_base + payload_offset` and jump there.

**Approach 1: Pop-through stack return (simplest, works in many cases)**

The stack overflow overwrites the saved return address. But what if it also overwrites *subsequent* stack entries? In the overflow zone:

```
Stack after overflow:
  [rsp+0]:     oa_base + 304  (payload address, overwrote saved callee-saved regs)
  [rsp+8]:     oa_base + 304  (this value is also at the mbuf chain!)
  ...
```

After the `memcpy` into the stack buffer, the stack is filled with the overflow data. But the **mbuf chain** (the source of the `memcpy`) still contains the same data at `oa_base + 304`. If the return address points to a gadget like `ret` (or more precisely, a gadget that does `pop ret; jmp ret`), and the top of the stack after return is `oa_base + 304`, then...

**This doesn't work directly** because the mbuf data is not on the stack. The `memcpy` copies data *from* the mbuf *to* the stack. After the copy, the stack has the data and the mbuf still has it — but they're in different memory regions. The return address on the stack points to stack memory, not mbuf memory.

**Correct approach: Indirect jump through a known kernel pointer.**

The `client` pointer (`struct svc_rpc_gss_client *client`) is passed into the function. It points to a kernel-allocated client structure that persists across requests. The attacker has previously communicated with this client (it's been established). The attacker may have been able to write data into this structure through previous RPC calls.

However, a more reliable approach exists:

**Approach 2: Compute the mbuf address relative to a known kernel base.**

Since FreeBSD 14.x has no KASLR, kernel data structures are at fixed addresses. The `rpc_gss_log_debug` and other logging functions, plus the GSS library functions, all have known addresses. The RPC layer places mbuf data at predictable offsets from the `m_ext` structure (which has a known base).

The attacker can:
1. Use the overflow to execute a small ROP chain that reads `curthread->td_retval` or similar to leak a known kernel address
2. Calculate the mbuf address from the leaked address
3. Jump to `mbuf + payload_offset`

But wait — this requires an extra round trip. Let me think of a single-request approach.

**Approach 3: Use the overflow data's own address.**

The key realization: `memcpy(buf, oa_base, oa_length)` copies data from mbuf to stack. After this copy, the **stack contains the attacker's data**. The return address that's overwritten is on the stack. The stack data and the mbuf data are **identical** at this point.

When the function returns:
1. `ret` pops the return address from the stack (e.g., `rsp = stack + 304`)
2. `jmp [rsp]` or `call [rsp]` — if the return address points to a gadget like `pop rdi; ret` followed by the address `oa_base + 304`

But `oa_base + 304` is **in the mbuf**, and the mbuf still exists in kernel memory at the time of return. So the `ret` pops `oa_base + 304` as the next return address, then the CPU jumps there — into the mbuf chain.

**This works!** The sequence is:

```
Stack at overflow end (offset 288-303):
  [288]:    gadget: "pop rdi; ret"
  [296]:    value:  oa_base + 304  (payload address in mbuf)
  [304]:    (not on stack — this is where the return address is)

Return address (at top of stack frame):  pop rdi; ret

Flow:
1. Function returns
2. CPU pops return address = pop_rdi_ret gadget address
3. CPU executes: pop rdi  → rdi = oa_base + 304
4. CPU executes: ret       → pops next return address
   But wait — the next value would come from the stack, which has been
   overwritten with the overflow data...

Actually, the stack at this point:
  The overflow filled the stack region. The return address was at some
  stack position. After popping it, rsp moves past the overflow zone.
  The data at the new rsp position comes from the NORMAL stack frame,
  NOT from the overflow.

So approach 3 needs the overflow to also control the subsequent stack values.
```

**This is the crux of the problem.** The 304-byte overflow controls a region of the stack. But after the return address is popped and the CPU executes the ROP chain, subsequent stack values come from the NORMAL stack frame (which is not under the attacker's control). The overflow region is exhausted.

#### Revised Approach 3: Indirect Jump Through the Overflow Data Itself

What if the ROP chain on the stack doesn't try to use subsequent stack values, but instead computes the payload address from a **pointer that already points to the mbuf data**?

The credential `oa` (`struct opaque_auth *`) is part of `msg->rm_call.cb_cred`. The `oa_base` field is a pointer into the mbuf chain. If the ROP chain can:

1. Load `oa_base` from a location the attacker controls
2. Add an offset to it
3. Jump to the result

**The 38 gadgets can do this:**

```
Stack ROP chain (within 304 bytes):
  [288]:  pop rdi; ret          → gadget
  [296]:  &msg->rm_call.cb_cred → address of the credential struct (known)
  [304]:  load rdi from rdi     → rdi = pointer to opaque_auth struct
  [312]:  load rdi from [rdi]   → rdi = oa_base (pointer to mbuf data)
  [320]:  add rdi, 304          → rdi = oa_base + 304 (payload start)
  [328]:  jmp *rdi              → indirect jump to payload
```

But `load rdi from rdi` requires a `mov rdi, [rdi]` gadget, which is uncommon. More commonly available:

```
  [288]:  pop rdi; ret          → gadget
  [296]:  &msg->rm_call.cb_cred → known kernel address
  [304]:  mov rax, [rdi]        → gadget: mov rax, [rdi]
  [312]:  add rax, 304          → gadget: add rax, imm32
  [320]:  jmp rax               → gadget: jmp rax
```

This needs 4 gadgets after the initial `pop rdi`, so **5 gadgets** to compute and jump to the payload address. Well within the 38-gadget budget.

**The challenge:** Can the attacker know the address of `msg->rm_call.cb_cred`? In a kernel context, `msg` is a local variable on the stack (`struct rpc_msg *msg`). The `msg` pointer is passed as a function argument. The address of `msg` itself is on the stack frame, and its content (the pointer to the `rpc_msg` struct) is at a fixed offset from `rsp`.

But the `rpc_msg` struct is allocated in the kernel's per-thread RPC state. On FreeBSD, this is typically `td_rpcmsg` in the `struct thread`. The address is derivable from `curthread`, which is a per-CPU variable at a known address (no KASLR).

**So the attacker can compute `&msg->rm_call.cb_cred` at exploit time** using:
- `curthread` (fixed address, known via `nm` or kernel debugging)
- Offset from `curthread` to `td_rpcmsg`
- Offset from `rpc_msg` to `cb_cred`

This requires the attacker to have access to the FreeBSD kernel source/symbols. For a known FreeBSD 14.x build, this is straightforward.

#### Full Exploit Plan Using Mbuf Payload

1. **Craft the mbuf chain:**
   - Bytes 0-303: overflow data for the stack (pop gadgets + computed return addresses)
   - Bytes 304+: full ROP payload (1000+ bytes) including uio setup, call chains

2. **Craft the stack overflow (304 bytes):**
   ```
   [0..31]:       Saved callee-saved registers (RBX, R12-R15, RBP)
   [32..39]:      Return address R0 → pop_rdi_ret gadget
   [40..47]:      &msg->rm_call.cb_cred (computed from known kernel layout)
   [48..55]:      Return address R1 → mov_rax_indirect gadget
   [56..63]:      Return address R2 → add_rax_imm32 gadget (add 304)
   [64..71]:      Return address R3 → jmp_rax gadget
   [72..303]:     Filler / preserved state
   ```

3. **Execution flow:**
   ```
   1. Function returns → jumps to pop_rdi_ret
   2. pop rdi → rdi = &msg->rm_call.cb_cred
   3. ret → jumps to mov_rax_indirect
   4. mov rax, [rdi] → rax = pointer to opaque_auth
   5. ret → jumps to add_rax_imm32
   6. add rax, 304 → rax = oa_base + 304 (payload in mbuf)
   7. ret → jumps to jmp_rax
   8. jmp rax → jumps to full ROP payload in mbuf
   9. Payload executes: setup uio, setup iovec, call kern_openat,
      call kern_writev, call __sys_close, ret to clean exit
   ```

**Total gadgets used:** 5 for the jump chain, well within the 38-gadget budget.

---

### Solution B: Multi-Round Stateful Exploitation

**Alternative approach:** Use multiple RPC requests in sequence, building state across requests.

1. **Request 1:** Establish a GSS security context, learn the client structure layout
2. **Request 2:** Use the overflow as an **arbitrary write primitive** to overwrite a function pointer or callback in the GSS client structure (pointed to by `client->cl_destroy` or similar)
3. **Request 3:** Trigger the overwritten callback, which jumps to attacker-controlled code

The advantage: each individual request has a smaller payload, but the state from previous requests enables the final exploit. The disadvantage: timing-dependent and requires the attacker to predict state.

---

### Solution C: Minimal Payload (No Full ROP Chain on Stack)

**Instead of writing an SSH key directly,** use the 304-byte overflow for a simpler primitive:

1. **Arbitrary kernel memory read** — Use `gss_verify_mic`'s error handling to leak kernel memory through error messages
2. **Arbitrary kernel memory write** — Forge a GSS token that causes `gss_init_sec_context` (or similar) to write to attacker-controlled addresses
3. **Chain to full exploit later** — Use the read/write primitive in a separate phase

The overflow establishes the primitive in the current request. A follow-up request leverages the established primitive for the actual payload.

---

### Solution D: Use Existing Kernel Functions as Payload

**JOP / PJP (Jump-oriented / Procedure-jump-oriented programming):** Instead of ROP gadgets that end with `ret`, use indirect calls to functions that already exist in the kernel and perform useful operations.

For example, FreeBSD kernel contains functions like:
- `copyout` — copy data from kernel to user
- `copyin` — copy data from user to kernel
- `kern_ksem_post` — signal a kernel semaphore
- Various syscall handlers

If an existing kernel function can write to a target location given a small set of register values, the exploit can use the overflow to set registers and indirect-call the function.

This reduces the gadget count because each function is a "macro" that does useful work.

---

## Recommended Approach

**Solution A (jump to mbuf payload) is the most practical.** Here's why:

| Factor | Solution A | Solution B | Solution C | Solution D |
|--------|------|-
| Round trips | 1 | 2+ | 2+ | 1+ |
| Timing dependence | None | High | Medium | Medium |
| Gadget complexity | Low (5 gadgets) | Medium | Medium | High |
| Payload size | 1000+ bytes in mbuf | Limited per-request | Primitive, not code | Limited |
| Stealth | High (one request triggers it) | Medium | Low (two requests) | Variable |

### Complete Exploit Flow (Solution A)

```
Attacker network buffer (mbuf chain):
┌─────────────────────────────────────────────────────┐
│ Bytes 0-303:    Stack overflow payload (304 bytes)  │
│   [0..31]:       Overwrite saved regs               │
│   [32..71]:      4-gadget chain: load+add+jump      │
│   [72..303]:     Filler                             │
├─────────────────────────────────────────────────────┤
│ Bytes 304-1303: ROP payload in mbuf (1000 bytes)    │
│   [304..367]:    setup uio struct in mbuf           │
│   [368..431]:    setup iovec in mbuf                │
│   [432..495]:    SSH key data                       │
│   [496..559]:    setup args for kern_openat          │
│   [560..623]:    call kern_openat                   │
│   [624..687]:    setup args for kern_writev          │
│   [688..751]:    call kern_writev                   │
│   [752..815]:    setup args for __sys_close          │
│   [816..879]:    call __sys_close                   │
│   [880..943]:    clean return chain                 │
│   [944..1007]:   padding                            │
├─────────────────────────────────────────────────────┤
│ Bytes 1008+:    Normal RPC data continuation        │
└─────────────────────────────────────────────────────┘

Stack during execution:
┌──────────────────────────────────────────┐
│ Normal stack (untouched)                  │
├──────────────────────────────────────────┤
│ Saved callee-saved regs ← OVERFLOW        │
│ [rbx, r12-r15, rbp]                      │
├──────────────────────────────────────────┤
│ Return addr ← OVERFLOW                    │
│ pop rdi; ret                              │
├──────────────────────────────────────────┤
│ ROP chain on stack ← OVERFLOW             │
│ pop rdi; mov rax,[rdi]; add rax,304; jmp rax │
└──────────────────────────────────────────┘

Flow:
1. svc_rpc_gss_validate returns
2. pop rdi; ret → rdi = &msg->rm_call.cb_cred
3. mov rax, [rdi] → rax = oa_base (pointer to mbuf)
4. add rax, 304 → rax = oa_base + 304 (payload in mbuf)
5. jmp rax → jumps into mbuf payload
6. Payload runs: opens file, writes SSH key, closes fd
7. Clean return to normal kernel execution
```

## Key Challenges

1. **Address computation:** The attacker must know the address of `msg->rm_call.cb_cred` at exploit time. This requires knowledge of the kernel's per-thread RPC state layout. Without KASLR, this is derivable from kernel symbols, but the exact offset depends on the FreeBSD version.

2. **Gadget availability:** The exploit requires specific gadgets:
   - `pop rdi; ret`
   - `mov rax, [rdi]; ret` (or `mov rax, [rsi]; ret` with pop rsi)
   - `add rax, imm32; ret`
   - `jmp rax` or `jmp rax; nop`

   FreeBSD's kernel is large (~2MB+), so these are almost certainly present. But the exact addresses must be known.

3. **Alignment:** sysv ABI requires 8-byte stack alignment before calls. The ROP chain in the mbuf payload must maintain alignment. The mbuf payload is under attacker control, so this is manageable (add `and rsp, -8` gadget if needed).

4. **Clean exit:** After writing the SSH key, the exploit must return cleanly. A kernel panic at this point is still an attack (it's a DoS), but a clean return is more stealthy and avoids interfering with follow-up exploits.

5. **Syscall numbers:** FreeBSD's syscall table changes between versions. The exploit must use the correct `kern_openat`, `kern_writev`, and `__sys_close` syscall numbers and function signatures.

6. **File path encoding:** The path `/root/.ssh/authorized_keys` must be passed correctly to `kern_openat`. This requires the string to be in attacker-controlled memory (the mbuf) and passed as a pointer.

## Summary

The 304-byte overflow **cannot hold the full 1000-byte payload inline** on the stack. The solution is to **use the 304 bytes as a bridge** — a small ROP chain (5 gadgets) that computes the address of a larger payload stored in the **mbuf chain** (the original network buffer, which persists in kernel memory and is much larger). The overflow sets up the jump from the stack to the mbuf payload, where the full SSH key write chain lives. This reduces the stack gadget count from ~125 (for the full payload) to just 4 (for the bridge), while leveraging the larger mbuf buffer for the actual payload.
