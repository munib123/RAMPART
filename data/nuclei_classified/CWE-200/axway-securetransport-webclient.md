# Vulnerability: Axway SecureTransport Web Client Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`axway-securetransport-webclient.yaml`)

## Description
AXWAY Secure Transport Web Client panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/html/skin/ric/C/config/default.config.json
```

