# Vulnerability: Paperless-ngx Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`paperless-ngx-panel.yaml`)

## Description
Detected Paperless-ngx was a self-hosted document management platform for scanning, OCR-ing and tagging paper documents.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/accounts/login/
```

