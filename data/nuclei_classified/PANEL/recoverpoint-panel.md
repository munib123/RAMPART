# Vulnerability: Dell EMC RecoverPoint Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`recoverpoint-panel.yaml`)

## Description
Dell EMC RecoverPoint management panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#!/welcome
```

