# Vulnerability: Ricoh Web Image Monitor - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ricoh-webimagemonitor-panel.yaml`)

## Description
Ricoh Web Image Monitor device was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web/guest/en/websys/webArch/header.cgi
```

