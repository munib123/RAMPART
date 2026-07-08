# Vulnerability: Eko Software Update Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`eko-software-update-panel.yaml`)

## Description
Eko software update panel for embedded systems was detected. An attacker can possibly upload a software image or restart the system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

