# Vulnerability: Wiren Board WebUI Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wiren-board-webui.yaml`)

## Description
Wiren Board WebUI panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#!/dashboards
```

