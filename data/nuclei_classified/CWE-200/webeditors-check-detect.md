# Vulnerability: Web Editor Check - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`webeditors-check-detect.yaml`)

## Description
Multiple web editor checks were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

