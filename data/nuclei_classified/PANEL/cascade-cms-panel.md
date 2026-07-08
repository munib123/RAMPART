# Vulnerability: Cascade CMS Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`cascade-cms-panel.yaml`)

## Description
Cascade CMS was detected — a web content management system for managing stand-out websites.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.act
```

