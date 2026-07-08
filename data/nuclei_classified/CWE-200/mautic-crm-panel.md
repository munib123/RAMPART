# Vulnerability: Mautic CRM Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mautic-crm-panel.yaml`)

## Description
Mautic CRM login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/s/login
```

