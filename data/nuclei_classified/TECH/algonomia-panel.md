# Vulnerability: Algonomia Leaf Platform Panel - Detect
**Classification:** TECH
**Source:** Nuclei Template (`algonomia-panel.yaml`)

## Description
Algonomia Leaf Platform login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/assets/i18n/en.json
```

