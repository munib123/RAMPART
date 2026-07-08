# Vulnerability: Avaya Aura System Manager Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`avayaaura-system-manager-panel.yaml`)

## Description
Avaya Aura System Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/network-login/
```

