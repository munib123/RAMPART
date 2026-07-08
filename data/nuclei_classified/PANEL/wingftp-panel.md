# Vulnerability: Wing FTP Server Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`wingftp-panel.yaml`)

## Description
Detects the presence of Wing FTP Server web interface

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

