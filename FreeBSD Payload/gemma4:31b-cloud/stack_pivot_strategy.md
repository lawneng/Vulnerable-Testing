# Overcoming ROP Chain Length Constraints: Stack Pivoting

## The Problem: ROP Chain Exhaustion
The available overflow provides $\approx 304$ bytes of controlled data. With an 8-byte return address per gadget on x86_64, this allows for roughly 38 gadgets. Complex kernel operations, such as writing an SSH key to disk via `kern_openat` and `kern_writev`, require complex structure setup (iovec, uio) and multiple function calls, necessitating a chain far longer than 38 gadgets (often $100+$ gadgets or $1\text{ KB}+$ of payload).

## The Solution: Stack Pivoting
To execute a massive payload when the initial overflow is limited, the attacker must perform a **Stack Pivot**. This technique redirects the CPU's stack pointer (`RSP`) to a larger, attacker-controlled memory region.

### 1. Identifying a Landing Zone
The attacker needs a region of memory they can write to and read from. In a kernel context, there are two primary options:
- **User-Space Mapping**: If SMAP (Supervisor Mode Access Prevention) is disabled or bypassed, the attacker can map a large page in user-space and pivot `RSP` directly to it.
- **Kernel Heap (Slab/Umap)**: The attacker can use "Heap Spraying" to place the larger ROP chain into a known or predictable location in the kernel heap.

### 2. Executing the Pivot
The initial 38-gadget "bootstrap" chain is used not to perform the final attack, but to perform the pivot. The attacker looks for a gadget that modifies `RSP`. Common examples include:
- `xchg rax, rsp; ret`
- `mov rsp, rdi; ret`
- `add rsp, 0x1000; ret` (if the payload was placed further down the stack)

**The Bootstrap Sequence:**
1. Use the first few gadgets to load the address of the "Landing Zone" into a register (e.g., `RAX`).
2. Execute the pivot gadget (`xchg rax, rsp`).
3. The CPU now treats the Landing Zone as the new stack.
4. The next `ret` instruction pops the first gadget of the **actual** $1\text{ KB}+$ payload from the Landing Zone.

### 3. Implementation for the SSH Key Payload
With the stack pivoted, the attacker has virtually unlimited space to:
1. **Construct Structures**: Use gadgets to write the `iovec` and `uio` structures into a known memory location.
2. **Prepare Arguments**: Load the necessary arguments for `kern_openat` (path, flags) and `kern_writev` (file descriptor, iovec pointer, count) into the correct registers.
3. **Execute Sequence**: Call the kernel functions in sequence to write the SSH public key to `/root/.ssh/authorized_keys`.
4. **Clean Up**: Pivot `RSP` back to the original stack or call a kernel exit routine to prevent a system panic.

## Summary of Strategy
| Stage | Limit | Goal | Technique |
| :--- | :--- | :--- | :--- |
| **Bootstrap** | 38 Gadgets | Divert Execution | `RSP` Pivot $\rightarrow$ Landing Zone |
| **Main Payload** | $\infty$ Gadgets | System Compromise | Full ROP Chain $\rightarrow$ `kern_writev` |

This approach transforms a limited "buffer overflow" into a "full memory control" primitive, allowing for complex multi-stage kernel exploitation.
