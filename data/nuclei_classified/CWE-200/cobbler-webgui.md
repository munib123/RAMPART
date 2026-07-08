# Vulnerability: Cobbler WebGUI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cobbler-webgui.yaml`)

## Description
Cobbler WebGUI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cobbler_web
```

