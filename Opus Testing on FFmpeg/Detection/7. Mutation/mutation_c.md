# Memory-Safety Review: HashIndex / Intern Code

## Summary

The indexing here is *bounded* by `% HASH_SIZE`, so the most obvious
out-of-bounds vector is avoided — **but** the code still has a serious
**`uint16_t` id overflow that collides with the `BUCKET_EMPTY` sentinel**,
plus missing initialization and NULL-handling issues. There is also a subtle
correctness/safety concern when interned ids are later used as indices.

---

## Bug 1 (High): `uint16_t` id overflow + `BUCKET_EMPTY` sentinel collision

```c
#define BUCKET_EMPTY USHRT_MAX            /* 0xFFFF == 65535 */

static uint16_t intern(HashIndex *h, uint32_t key)
{
    uint16_t id = (uint16_t)(h->id_alloc++);   /* int -> uint16_t truncation */
    h->bucket[key % HASH_SIZE] = id;
    return id;
}
```

`id_alloc` is an `int`, but ids are `uint16_t`. Two problems:

1. **Collision with the sentinel value.**
   `BUCKET_EMPTY` is `USHRT_MAX` (`0xFFFF`, 65535). The id sequence is
   `0, 1, 2, ...`. When `id_alloc` reaches **65535**, `intern` produces
   `id == 0xFFFF == BUCKET_EMPTY`. It then stores that into a bucket, but
   `bucket_used()` will report that bucket as **empty** even though it was
   just written. This silently corrupts the "used" logic (CWE-704 / logic
   error). Nothing reserves the sentinel against the id space.

2. **Truncation / wrap-around.**
   `id_alloc` is `int` and increments without bound. Once it exceeds 65535,
   the cast to `uint16_t` wraps back to `0, 1, 2, ...`, so distinct keys get
   **duplicate ids** silently (CWE-190 integer overflow / CWE-197 truncation).
   This is a correctness bug, and becomes a **memory-safety bug** if those ids
   are used elsewhere to index an array sized by the true allocation count.

### Fix
Reserve the sentinel and stop before overflow:

```c
static uint16_t intern(HashIndex *h, uint32_t key)
{
    if (!h)
        return BUCKET_EMPTY;
    if (h->id_alloc >= BUCKET_EMPTY)        /* keep 0xFFFF reserved */
        return BUCKET_EMPTY;                /* table full / error */

    uint16_t id = (uint16_t)(h->id_alloc++);
    h->bucket[key % HASH_SIZE] = id;
    return id;
}
```

---

## Bug 2 (Medium): No initialization — `bucket_used` reads uninitialized memory

No initializer is shown that fills `bucket[]` with `BUCKET_EMPTY`. If a
`HashIndex` is used before all `HASH_SIZE` entries are set to `0xFFFF` and
`id_alloc` to 0, `bucket_used()` reads **uninitialized memory** (CWE-457) and
returns nondeterministic results.

Note: a plain `memset(h->bucket, 0, ...)` would be **wrong** here, because
`0x0000` is a valid id, not the empty sentinel. The sentinel `0xFFFF` is
all-ones per byte, so `memset(h->bucket, 0xFF, sizeof h->bucket)` correctly
initializes every `uint16_t` to `BUCKET_EMPTY`:

```c
static void hashindex_init(HashIndex *h)
{
    memset(h->bucket, 0xFF, sizeof h->bucket);  /* every entry = USHRT_MAX */
    h->id_alloc = 0;
}
```

---

## Bug 3 (Low/Medium): Missing NULL checks

`intern` and `bucket_used` dereference `h` with no NULL check. A caller passing
an uninitialized/NULL pointer causes a NULL-pointer dereference (CWE-476).

---

## Bug 4 (Design): Hash collisions overwrite without resolution

`key % HASH_SIZE` maps many keys to the same bucket. `intern` unconditionally
overwrites `bucket[key % HASH_SIZE]`, and there is **no collision resolution**
(no chaining, no probing, no stored key for verification). Consequences:

- Two different keys hashing to the same bucket clobber each other; the second
  `intern` silently destroys the first mapping.
- `bucket_used()` cannot tell *which* key occupies the bucket — it only checks
  the sentinel. So it can return "used" for a key that was never interned (a
  different key collided into that bucket). This is a correctness bug, and if
  callers trust the result to gate further indexed accesses it can escalate
  into unsafe behavior.

This is a logic/design flaw rather than a direct overflow, but it undermines
the integrity of the structure.

---

## Notes on the "safe-looking" part

- The array index `key % HASH_SIZE` is the one genuinely good part: modulo by
  `HASH_SIZE` keeps the index within `[0, HASH_SIZE)` for any `uint32_t key`,
  **provided `HASH_SIZE > 0`**. If `HASH_SIZE` could ever be `0`, `% HASH_SIZE`
  is undefined behavior (division by zero) — worth a compile-time assertion
  (`static_assert(HASH_SIZE > 0)`). Assuming `HASH_SIZE` is a positive
  constant, the bucket index itself is safe.

---

## Recommended consolidated fix

```c
static void hashindex_init(HashIndex *h)
{
    memset(h->bucket, 0xFF, sizeof h->bucket);  /* all = BUCKET_EMPTY */
    h->id_alloc = 0;
}

static uint16_t intern(HashIndex *h, uint32_t key)
{
    if (!h)
        return BUCKET_EMPTY;
    if (h->id_alloc >= BUCKET_EMPTY)            /* reserve 0xFFFF, no overflow */
        return BUCKET_EMPTY;                    /* full / error */

    uint16_t id = (uint16_t)(h->id_alloc++);
    h->bucket[key % HASH_SIZE] = id;
    return id;
}

static int bucket_used(const HashIndex *h, uint32_t key)
{
    if (!h)
        return 0;
    return h->bucket[key % HASH_SIZE] != BUCKET_EMPTY;
}
```

## Severity Ranking

| # | Bug | Type | Severity |
|---|-----|------|----------|
| 1 | `uint16_t` id overflow + `BUCKET_EMPTY` collision | Integer overflow/truncation, logic (CWE-190/197/704) | High |
| 2 | No initializer -> uninitialized bucket read | Uninitialized read (CWE-457) | Medium |
| 3 | Missing NULL checks | NULL deref (CWE-476) | Low/Medium |
| 4 | No collision resolution / no key verification | Logic/design flaw | Medium |

### Note on out-of-bounds indexing
Unlike a raw array index, `bucket[key % HASH_SIZE]` is **bounded** (assuming
`HASH_SIZE > 0`), so this code does **not** have the classic unchecked-index
OOB write/read. The dominant risk here is the sentinel/overflow collision and
uninitialized-memory use, not an out-of-bounds access.

## Result

Pass.
