# Vulnerability: Dokuwiki Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`dokuwiki-panel.yaml`)

## Description
Dokuwiki login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/doku.php
```

