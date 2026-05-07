# Case 4: Staging a Large ROP Chain in a Constrained Overflow

## The Problem

The overflow provides ~304 bytes past the header — roughly 38 gadgets on x86-64 (304 / 8). A full chain to write an SSH key via `kern_openat` + `kern_writev` (including constructing `iovec`/`uio` structs in kernel memory) exceeds 1000 bytes. 38 gadgets is insufficient.

## The Solution: Stack Pivoting

Use a small number of gadgets from the 38-gadget budget to redirect RSP to a much larger, attacker-controlled buffer containing the full ROP chain. This is the standard technique for constrained overflow exploitation.

### Budget Allocation

| Phase | Gadgets | Purpose |
|-------|---------|---------|
| Pre-pivot setup | 2–3 | Populate a register with the target address; disable SMAP if needed |
| Pivot | 1 | Redirect RSP to the larger buffer |
| Remaining | 33–35 | Unused — the real chain runs from the pivot target |
| **Full chain** | ~125+ | Executes from the pivot target buffer |

### How the Pivot Works

The overflow overwrites callee-saved registers (RBX, R12–R15), saved RBP, and the return address. On function return, the callee-saved registers are restored *before* `ret` pops the return address. This means the attacker can pre-load a register with an arbitrary value, then chain to a pivot gadget that moves that register into RSP:

```asm
; Gadget 1 (return address): xchg rbx, rsp; ret
;   — RSP now points to attacker-controlled buffer
;   — execution continues from the full ROP chain there
```

Or equivalently: `mov rsp, r12; ret` or any register-to-RSP transfer gadget. These are common in large kernel binaries.

### Where to Pivot To

Three options, in order of robustness:

**Option A: Userland mmap'd page**

The attacker process calls `mmap(MAP_FIXED, 0x1337000, ...)` and writes the full ROP chain to that page. The pivot redirects RSP to `0x1337000`. The chain then executes from userland memory.

Challenge: **SMAP** (Supervisor Mode Access Prevention), if enabled on FreeBSD 14.x, prevents the kernel from reading userland pages. The CPU would fault on the first `ret` that pops from the userland stack.

Solution: Disable SMAP before pivoting. Insert 1–2 gadgets before the pivot that execute the `stac` instruction (sets the AC flag in RFLAGS, which temporarily disables SMAP) or clear the SMAP bit in CR4. These gadgets exist in the kernel text (FreeBSD's `copyin`/`copyout` paths use `stac`/`clac`). After SMAP is off, the pivot to userland proceeds without fault.

```
Stack layout (in overflow):
  [overwritten RBX = 0x1337000]     ← restored before ret
  [overwritten R12-R15]             ← restored before ret
  [overwritten RBP]
  [return addr → gadget: stac; ret] ← gadget 1: disable SMAP
  [next addr → gadget: xchg rbx, rsp; ret]  ← gadget 2: pivot
  ...userland ROP chain continues at 0x1337000...
```

**Option B: Kernel heap spray (avoids SMAP entirely)**

Since there is no KASLR, kernel heap addresses are predictable with controlled allocation patterns. The attacker:

1. Sends many legitimate RPC requests to allocate kernel heap buffers filled with a `ret` sled followed by the full ROP chain. Each request's credential body is a kernel `malloc(9)` allocation containing attacker data.
2. Through heap feng shui (controlling allocation sizes and timing), places one of these buffers at a predictable kernel virtual address.
3. Pivots RSP to that address. Since the buffer is in kernel memory, SMAP is not a concern.

The RPC service itself is the spray vehicle — each incoming request causes the kernel to allocate buffers for the XDR-decoded credential and verification data. The attacker can deterministically fill uma zones with controlled content.

**Option C: Pivot to the credential buffer itself**

The `oa_base` buffer (the RPC credential body) is already in kernel memory and contains attacker-controlled data. The `memcpy` copies it *into* `rpchdr`, but the *source* buffer in the kernel heap still holds the original data. If the attacker can predict the address of this heap buffer (via heap layout analysis — feasible without KASLR), they can pivot directly to it.

The attacker structures `oa_base` so that at the offset where RSP will land after the pivot, the full ROP chain begins. The first `oa_length` bytes are consumed by the `memcpy` (copied into `rpchdr`), but the source buffer remains intact and reusable as the pivot target.

This is the most efficient option — no separate spray step is needed. The credential buffer *is* the payload staging area.

### Full Exploitation Flow

```
1. Attacker process mmap(MAP_FIXED) a page at chosen address,
   writes full ROP chain + iovec/uio struct data.

2. Craft RPC packet with oa_length > 96 (e.g., 350).

3. Overflow layout on kernel stack:
   [32 bytes: header fields, don't-care]
   [96 bytes: padding to reach callee-saved regs]
   [RBX = pivot target address]
   [R12-R15 = useful constants for the full chain]
   [RBP = don't-care]
   [ret addr → stac; ret]          ← disable SMAP
   [next    → xchg rbx, rsp; ret]   ← pivot RSP to userland page

4. svc_rpc_gss_validate returns:
   - Callee-saved regs restored (RBX = pivot target)
   - SMAP disabled by stac gadget
   - RSP pivoted to mmap'd page
   - Full chain executes: kern_openat → kern_writev → clac (re-enable SMAP) → clean return

5. SSH key written to /root/.ssh/authorized_keys.
```

### Key Challenges and Solutions

| Challenge | Solution |
|-----------|----------|
| 38 gadgets too few | Stack pivot to larger buffer (3–5 gadgets for pivot) |
| SMAP blocks userland reads | `stac` gadget before pivot; `clac` after chain completes |
| Knowing the pivot target address | Userland: `mmap(MAP_FIXED)`. Kernel heap: no KASLR + heap feng shui |
| Constructing iovec/uio in kernel memory | Embed struct layouts in the mmap'd page; ROP chain populates pointers into them |
| Clean return after exploitation | Restore SMAP with `clac`, reset stack to a valid frame, or let the worker thread exit via `kthread_exit()` |

### Why This Works

The stack pivot decouples the *overflow size* from the *chain size*. The 304-byte overflow is only used to: (1) set up register values, (2) disable SMAP, and (3) redirect the stack. Once RSP points to the attacker's larger buffer, chain length is effectively unlimited — constrained only by the size of the mmap'd page or heap buffer, not by the overflow.