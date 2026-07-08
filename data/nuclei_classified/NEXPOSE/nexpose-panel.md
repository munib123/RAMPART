# Vulnerability: Rapid7 Nexpose VM Security Console - Detect
**Classification:** NEXPOSE
**Source:** Nuclei Template (`nexpose-panel.yaml`)

## Description
Rapid7 Nexpose VM Security Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.jsp
```

