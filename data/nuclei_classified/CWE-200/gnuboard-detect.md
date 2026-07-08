# Vulnerability: Gnuboard CMS - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gnuboard-detect.yaml`)

## Description
Gnuboard CMS was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/LICENSE.txt
```

