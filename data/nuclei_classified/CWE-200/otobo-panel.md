# Vulnerability: OTOBO Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`otobo-panel.yaml`)

## Description
OTOBO login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/otobo/index.pl
```

