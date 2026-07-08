# Vulnerability: PaperCut NG Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`papercut-ng-panel.yaml`)

## Description
PaperCut is a print management system. Log in to manage your print quotas, see your print history and configure your system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user
```

