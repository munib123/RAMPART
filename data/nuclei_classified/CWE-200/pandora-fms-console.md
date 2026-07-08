# Vulnerability: Pandora FMS Mobile Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pandora-fms-console.yaml`)

## Description
Pandora FMS Mobile Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pandora_console/mobile/
```

