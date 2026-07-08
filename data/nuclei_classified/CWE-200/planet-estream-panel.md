# Vulnerability: Planet eStream Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`planet-estream-panel.yaml`)

## Description
Planet eStream login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login.aspx
```

