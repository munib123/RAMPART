# Vulnerability: Mitel MiCollab Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`mitel-micollab-panel.yaml`)

## Description
Mitel MiCollab login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wd/en-us/wapplink.asp
GET {{BaseURL}}/portal/
```

