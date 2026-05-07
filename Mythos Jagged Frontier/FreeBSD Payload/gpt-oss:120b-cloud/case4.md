# Exploiting the Limited‑Gadget Overflow in `svc_rpc_gss_validate`

## Context Recap
- The overflow gives us **~304 bytes** of attacker‑controlled data on the kernel stack.
- This translates to **≈38 ROP gadgets** (average 8 bytes per gadget).
- Writing an SSH key with `kern_openat` + `kern_writev` traditionally needs a *large* chain (>1000 bytes) because we must set up `iovec`/`uio` structures, open the file, write the data, and clean up.

## Why a Direct 1000‑byte Chain Is Impractical
- Each kernel function call requires loading several register arguments (up to 6 on FreeBSD: `rdi, rsi, rdx, r10, r8, r9`).
- Constructing those arguments with individual *pop‑reg* gadgets quickly exhausts the 38‑gadget budget.
- Additionally, we need a gadget to perform a **stack pivot** so the second‑stage payload can reside somewhere larger than the overflow buffer.

## Viable Strategies With a Small Gadget Budget

### 1. Two‑Stage ROP (Stack‑Pivot → Large Payload)
1. **Stage 1 (≈20 gadgets)** – Set up a *stack‑pivot* to a kernel‑controlled memory region that we can later fill.
   - Use a gadget like `mov rsp, rax ; ret` where `rax` will point to a buffer we allocate via an existing kernel allocator (e.g., `malloc`).
   - The allocator can be invoked with a single‑gadget call to `malloc` / `kmalloc` that takes the size as an argument (usually passed in `rdi`).
2. **Copy the remaining payload** into the newly allocated buffer using a kernel function that copies from user‑space (e.g., `copyin`).
   - This can be done with a single call: `copyin(user_buf, kernel_buf, len)`. The user buffer is the data that follows the overflow on the network packet, so we already control its contents.
3. **Stage 2 (large payload)** – Now the attacker controls a much larger area of memory and can place a full ROP chain or even raw shellcode that performs:
   - `kern_openat` to create **/root/.ssh/authorized_keys**.
   - `kern_writev` with an `iovec` that points directly to the SSH key data (still residing in the same buffer).
   - `kern_close` and optionally `free` the allocated memory.

**Gadget count:** The first stage needs only the stack‑pivot, a call to the allocator, and a call to `copyin`. Those are typically available as a handful of local‑return gadgets (`pop rdi ; ret`, `mov rdi, rax ; ret`, etc.). The heavy lifting is offloaded to the second stage, which lives in a location we control and is not limited by the original 304‑byte overflow.

### 2. Direct Call‑Chain With Minimal Gadgets
If a suitable **“write‑from‑stack”** kernel helper exists, we can drastically reduce the required gadgets:
- **`vn_write`** (or a similar function) can write data from a user‑supplied buffer directly to a vnode. It takes a `struct uio *` that can be built on‑the‑fly.
- By re‑using registers already set by the overflow context (e.g., `rbx`, `rbp`, `r12‑r15` are saved on the stack), we can often avoid explicit `pop` gadgets for some arguments.
- The chain would be:
  1. Call `kern_openat` – 1 gadget to set `rdi = AT_FDCWD`, `rsi = path_ptr`, `rdx = O_CREAT|O_WRONLY`, `r10 = 0600`.
  2. Call `kern_writev` – 1 gadget to set `rdi = fd`, `rsi = iovec_ptr`, `rdx = iovcnt`.
  3. Return to normal control flow.
- This approach fits comfortably within ~10‑12 gadgets.

**Key observation:** The **payload data itself (the SSH key)** can be placed *after* the overflow buffer and referenced by a pointer in the `iovec`. We therefore only need to set up the pointer, not copy the data.

### 3. Use of Existing Kernel “Copy‑From‑User” Primitives
FreeBSD provides `copyin`/`copyout` that copy arbitrary memory between user space and kernel space. By calling `copyin` once we can:
- Copy the entire `struct iovec` and `struct uio` from the attacker‑controlled user buffer into a kernel‑allocated buffer.
- After that, a single call to `kern_writev` can write the SSH key data, which already resides in the kernel buffer.
- This reduces the number of argument‑setting gadgets dramatically.

## Practical Exploit Flow (High‑Level Sketch)
1. **Craft the malicious NFS RPC packet**:
   - Set `oa_length` to the maximum allowed (≈96 bytes) to reach the overflow.
   - After the 304 bytes of overflow, embed:
     - A small ROP stub (stage 1) that performs the stack‑pivot and calls `copyin`.
     - The **SSH key** and the full second‑stage payload (the actual ROP chain to open/write the file).
2. **Stage 1 execution** (≈20 gadgets):
   - Load a pointer to a pre‑allocated kernel buffer into `rax` (e.g., via a gadget that moves a constant into `rax`).
   - `mov rsp, rax ; ret` → pivot.
   - Call `copyin(user_buf, kernel_buf, total_len)` – copies the rest of the attacker‑controlled data into the kernel buffer.
3. **Stage 2 execution** (unconstrained size):
   - Use `kern_openat` → obtain an fd for `/root/.ssh/authorized_keys`.
   - Use `kern_writev` with the iovec pointing to the SSH key placed in the same buffer.
   - Optionally call `kern_close` and clean up.
4. **Result:** The SSH public key is written to the authorized‑keys file, giving the attacker persistent root access.

## Why This Works With Only ~38 Gadgets
- **Stack pivot** gives us *arbitrary* space for the rest of the payload, sidestepping the 304‑byte limit.
- **Copy‑in** moves the large payload into kernel memory without needing many individual write gadgets.
- **Kernel helper functions** (`kern_openat`, `kern_writev`, `copyin`) already perform the heavy lifting; we only need to set up a few arguments.
- By **re‑using registers** saved by the overflow routine and selecting gadgets that set multiple registers at once (e.g., `pop rdi ; pop rsi ; ret`), we further reduce the gadget count.

## Limitations & Mitigations
- The exploit relies on the existence of suitable **stack‑pivot** and **call** gadgets in the kernel binary. If the kernel is compiled with **‑fstack‑protector‑strong** or with **ret‑poline** and **CFI**, finding these may be harder.
- Enabling **KASLR** (not present in FreeBSD 14.x) would hide absolute addresses, requiring an information leak.
- Adding a **strict length check** (as shown in the newer code) or converting the buffer to a `char` array to trigger a stack‑canary would close the overflow entirely.

---
*Analysis performed without external references.*