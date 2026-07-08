# Vulnerability: BeyondTrust Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`beyondtrust-panel.yaml`)

## Description
BeyondTrust login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/WebConsole/
```

