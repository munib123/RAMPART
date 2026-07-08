# Vulnerability: Micro Focus Vibe Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`microfocus-vibe-panel.yaml`)

## Description
Micro Focus Vibe login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ssf/s/portalLogin
```

