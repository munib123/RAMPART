# Vulnerability: Veracore Login - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`veracore-panel.yaml`)

## Description
A veracore login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/veracore/Home/#systems
```

