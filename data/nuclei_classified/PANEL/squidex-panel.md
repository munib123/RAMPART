# Vulnerability: Squidex Headless CMS Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`squidex-panel.yaml`)

## Description
Squidex is an open source headless CMS and content management hub.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/favicon.ico
```

