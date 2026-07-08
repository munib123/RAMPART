# Vulnerability: Peplink Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`peplink-panel.yaml`)

## Description
peplink login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/MANGA/index.cgi
```

