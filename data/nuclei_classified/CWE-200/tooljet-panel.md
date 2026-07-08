# Vulnerability: ToolJet Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tooljet-panel.yaml`)

## Description
ToolJet login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login?redirectTo=/
```

