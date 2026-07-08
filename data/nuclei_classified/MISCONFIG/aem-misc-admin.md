# Vulnerability: Adobe AEM Misc Admin Dashboard Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aem-misc-admin.yaml`)

## Description
Adobe AEM Misc Admin Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

