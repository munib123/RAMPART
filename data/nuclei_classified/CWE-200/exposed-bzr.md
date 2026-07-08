# Vulnerability: Bazaar Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-bzr.yaml`)

## Description
Bazaar configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.bzr/branch/branch.conf
```

