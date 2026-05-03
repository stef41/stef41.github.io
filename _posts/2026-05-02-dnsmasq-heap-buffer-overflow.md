---
layout: post
title: "dnsmasq: Heap Buffer Overflow in DNS Cache Insertion (CVSS 9.8)"
date: 2026-05-02
tags: [heap-overflow, rce, dns, cwe-122]
---

## Summary

A heap buffer overflow in dnsmasq's DNS cache insertion path allows **remote code execution as root** via a single crafted DNS response. The bug affects all versions through 2.92 and the current git HEAD (commit `fc22868`).

- **CVSS 3.1:** 9.8 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CWE:** CWE-122 (Heap-based Buffer Overflow)
- **Affected:** all dnsmasq versions through 2.92
- **Status:** Reported to vendor on 2026-05-02, 90-day coordinated disclosure

## The Bug

The vulnerability is a size mismatch between two representations of a DNS name.

### Wire-format validation in `extract_name()`

`extract_name()` in `rfc1035.c` validates DNS name length using the **wire-format** byte count:

```c
namelen += l + 1;
if (namelen >= MAXDNAME)
    return 0;
```

`MAXDNAME` is 1025. A name with 16 labels of 63 null bytes is 1024 bytes on the wire — passes the check.

### NAME_ESCAPE expansion

When `NAME_ESCAPE` processing is active, certain bytes expand to 2 output bytes in the printable name:

| Byte on wire | Output        | Expansion |
|-------------|---------------|-----------|
| `0x00`      | `\000`-style  | 1 → 2     |
| `0x2e` (`.`)| escaped dot   | 1 → 2     |
| `0x01`      | escaped       | 1 → 2     |

A name that is 1024 bytes on the wire can expand to **~2032 bytes** in the output buffer.

`extract_name()` writes into `daemon->namebuff` which is `MAXDNAME*2+1 = 2051` bytes — large enough. No overflow here.

### The overflow: `really_insert()` in `cache.c`

The overflow occurs when `really_insert()` copies the expanded name into the cache:

```c
strcpy(cache_get_name(new), name);
```

The destination is a `union bigname` buffer of only **`MAXDNAME = 1025` bytes**. The expanded name is ~2032 bytes. This results in **up to ~1007 bytes** of attacker-controlled data overflowing past the end of the `bigname` buffer into adjacent heap objects.

## Exploitation

The overflow corrupts adjacent cache entries and the `big_free` freelist, which has **no integrity checks**. This enables:

1. **Arbitrary-address allocation** via `big_free` freelist corruption
2. **Remote code execution** — a working exploit exists for 32-bit targets using freelist corruption to overwrite `__free_hook`
3. **DNS cache poisoning** for arbitrary domains

On 32-bit targets with ASLR, brute-force is feasible (~2 hours) because `fork()`-based TCP handling means child crashes don't kill the parent process.

## Trigger Conditions

The victim's dnsmasq must have **negative caching active** (`--neg-ttl` or upstream SOA). This is the default in:

- **Pi-hole**
- **OpenWrt**
- **libvirt/KVM**
- Most consumer routers

The query name must be >50 characters to force `bigname` freelist allocation. A single DNS query from any client behind the dnsmasq instance is sufficient.

## Attack Scenario

1. Attacker registers a domain and controls its authoritative DNS server
2. The malicious nameserver returns a CNAME whose target contains 16 labels of 63 null bytes each
3. Any client behind the target dnsmasq resolves a name under the attacker's domain
4. dnsmasq caches the response → heap overflow → RCE as root

## Affected Components

- `rfc1035.c` — `extract_name()` function (wire-format length validation)
- `cache.c` — `really_insert()` function (`strcpy` into `union bigname`)

## Timeline

| Date | Event |
|------|-------|
| 2026-05-02 | Vulnerability discovered and reported to vendor |
| 2026-05-02 | CVE requested from MITRE |
| TBD | Vendor response |
| TBD | Fix released |

## References

- [dnsmasq git repository](https://thekelleys.org.uk/git/dnsmasq.git)
- [dnsmasq project page](https://thekelleys.org.uk/dnsmasq/)
