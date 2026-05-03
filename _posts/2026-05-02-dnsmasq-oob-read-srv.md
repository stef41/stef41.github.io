---
layout: post
title: "dnsmasq: Out-of-Bounds Read via SRV Record with rdlen=0 (CVSS 7.5)"
date: 2026-05-02
categories: [security, vulnerability, dnsmasq]
tags: [oob-read, dos, dns, cwe-125, srv]
---

## Summary

An out-of-bounds read in dnsmasq's DNS response processing causes a **crash (DoS)** and potential **information disclosure** when handling a malicious SRV record with `rdlen=0`. The bug affects all versions through 2.92 and current git HEAD (commit `fc22868`).

- **CVSS 3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CWE:** CWE-125 (Out-of-bounds Read)
- **Affected:** all dnsmasq versions through 2.92
- **Status:** Reported to vendor on 2026-05-02, 90-day coordinated disclosure

## The Bug

The vulnerability is in `extract_addresses()` in `rfc1035.c`, specifically in the SRV record (type 33) handling path.

### RR Descriptor for SRV

dnsmasq defines RR processing descriptors that describe how to parse the RDATA section. For SRV records, the descriptor is:

```
{6, 0, -1}
```

This means: skip 6 bytes of fixed fields (priority, weight, port), then extract a domain name (target).

### The Bounds Check Flaw

When `rdlen=0`, the 6-byte skip is clamped to 0 via the bounds check:

```c
if (desc > endrr - p1)
    desc = endrr - p1;
```

But `extract_name()` is **still called** with `p1` pointing at `endrr`. There is no check that any data remains for the domain name extraction.

### What Happens

`extract_name()` reads data **beyond the record's RDATA boundary**, interpreting bytes from subsequent resource records or the packet trailer as a domain name. This continues until it hits unmapped memory (crash) or finds a valid name terminator.

## Impact

1. **Denial of Service** — immediate crash when the read reaches unmapped memory. Triggers immediately under AddressSanitizer.
2. **Information Disclosure** — if heap data beyond the DNS packet is parsed as a domain name and cached, subsequent queries could retrieve the leaked data from the cache.

## Attack Scenario

1. Attacker registers a domain and controls its authoritative DNS server
2. The malicious nameserver returns an SRV record with `rdlen=0`
3. Any client behind the target dnsmasq issues an SRV query for the attacker's domain (e.g., `_sip._tcp.evil.com`)
4. dnsmasq processes the response → out-of-bounds read → crash

A single malicious DNS response is sufficient. No authentication or user interaction is required.

## Affected Components

- `rfc1035.c` — `extract_addresses()` function, SRV record type 33 handling

## Proof of Concept

The bug triggers immediately when running dnsmasq under AddressSanitizer:

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x...
    #0 extract_name rfc1035.c:xxx
    #1 extract_addresses rfc1035.c:xxx
```

## Fix

The fix should verify that sufficient RDATA remains after skipping fixed fields before calling `extract_name()`:

```c
if (p1 >= endrr)
    return 0;  // no data left for domain name
```

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
