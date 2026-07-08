# Vulnerability: Matomo Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`matomo-panel.yaml`)

## Description
google analytics alternative that protects your data and your customers privacy.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/index.php
GET {{BaseURL}}/plugins/CoreHome/images/favicon.png
```

