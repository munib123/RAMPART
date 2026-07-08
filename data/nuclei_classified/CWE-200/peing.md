# Vulnerability: Peing User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`peing.yaml`)

## Description
Peing user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://peing.net/api/v2/items/?type=answered&account={{user}}
```

