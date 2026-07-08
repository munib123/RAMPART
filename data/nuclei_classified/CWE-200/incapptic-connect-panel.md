# Vulnerability: Ivanti Incapptic Connect Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`incapptic-connect-panel.yaml`)

## Description
Ivanti Incapptic Connect panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/static/img/custom_icons/favicon.ico
```

