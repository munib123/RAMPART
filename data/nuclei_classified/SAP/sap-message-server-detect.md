# Vulnerability: SAP Message Server HTTP - Detect
**Classification:** SAP
**Source:** Nuclei Template (`sap-message-server-detect.yaml`)

## Description
Detected SAP Message Server by sending an HTTP request to the root path and checking for SAP Message Server header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{RootURL}}
```

