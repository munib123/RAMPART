# Vulnerability: FatPipe WARP - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fatpipe-warp-panel.yaml`)

## Description
the FatPipe WARP administration panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/fpui/jsp/login.jsp
```

