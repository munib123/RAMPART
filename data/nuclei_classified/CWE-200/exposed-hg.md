# Vulnerability: HG Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-hg.yaml`)

## Description
HG configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.hg/hgrc
```

