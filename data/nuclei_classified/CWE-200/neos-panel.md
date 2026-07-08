# Vulnerability: Neos CMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`neos-panel.yaml`)

## Description
Neos CMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/neos/login
```

