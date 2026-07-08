# Vulnerability: OpenSign Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`opensign-panel.yaml`)

## Description
OpenSign Login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/locales/en/translation.json
GET {{BaseURL}}/
```

