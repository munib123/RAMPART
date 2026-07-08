# Vulnerability: FatPipe MPVPN - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fatpipe-mpvpn-panel.yaml`)

## Description
The admin panel of the FatPipe MPVPN has been discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/fpui/jsp/login.jsp
```

