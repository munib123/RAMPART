# Vulnerability: CATALOGcreator Page Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`catalog-creator-detect.yaml`)

## Description
CATALOGcreator Page login panel detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/index.php
```

