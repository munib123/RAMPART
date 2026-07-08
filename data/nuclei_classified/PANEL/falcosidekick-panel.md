# Vulnerability: Falcosidekick UI Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`falcosidekick-panel.yaml`)

## Description
Falcosidekick UI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/
```

