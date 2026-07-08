# Vulnerability: SAP ICM Admin Web Interface
**Classification:** SAP
**Source:** Nuclei Template (`sap-public-admin.yaml`)

## Description
The SAP ICM (Internet Communication Manager) admin monitor interface is often set to public and can be accessed without authentication. The interface discloses version information about the underlying operating system, a brief SAP patch level overview, running services including their corresponding ports and more.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sap/admin/public/index.html
```

