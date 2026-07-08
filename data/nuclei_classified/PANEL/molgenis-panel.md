# Vulnerability: Molgenis Panel - Exposure
**Classification:** PANEL
**Source:** Nuclei Template (`molgenis-panel.yaml`)

## Description
Molgenis emx2 data platform is a software that provides a web-based interface for managing and analyzing data. It might contain sensitive information without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api
```

