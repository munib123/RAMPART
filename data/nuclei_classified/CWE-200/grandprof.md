# Vulnerability: Grandprof User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`grandprof.yaml`)

## Description
Grandprof user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://grandprof.org/communaute/{{user}}
```

