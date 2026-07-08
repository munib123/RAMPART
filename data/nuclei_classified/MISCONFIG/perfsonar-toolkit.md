# Vulnerability: perfSONAR Toolkit - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`perfsonar-toolkit.yaml`)

## Description
perfSONAR Toolkit is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/toolkit/
```

