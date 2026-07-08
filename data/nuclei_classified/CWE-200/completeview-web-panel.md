# Vulnerability: CompleteView Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`completeview-web-panel.yaml`)

## Description
CompleteView panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/en-US/login?return=/live-view
```

