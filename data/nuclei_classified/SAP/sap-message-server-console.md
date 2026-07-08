# Vulnerability: SAP Message Server Console - Exposure
**Classification:** SAP
**Source:** Nuclei Template (`sap-message-server-console.yaml`)

## Description
Detected the SAP Message Server HTTP console on /msgserver. When accessed directly, the message server returns an HTML page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{RootURL}}/msgserver
```

