# Vulnerability: ADFS Detect
**Classification:** TECH
**Source:** Nuclei Template (`adfs-detect.yaml`)

## Description
Detects ADFS with forms-based authentication enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/adfs/ls/idpinitiatedsignon.aspx
```

