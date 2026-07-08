# Vulnerability: Intelbras DVR - Unrestricted Access
**Classification:** UNAUTH
**Source:** Nuclei Template (`intelbras-dvr-unauth.yaml`)

## Description
The HTTP GET request to /cap.js on the server Intelbras DVR reveals several potentially sensitive pieces of information that are not properly protected or encrypted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cap.js
```

