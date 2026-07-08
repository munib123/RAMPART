# Vulnerability: SAP Web Dispatcher admin portal detection
**Classification:** SAP
**Source:** Nuclei Template (`sap-web-dispatcher-admin-portal.yaml`)

## Description
Detection of SAP Web Dispatcher Admin Portal

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sap/wdisp/admin/public/default.html
```

