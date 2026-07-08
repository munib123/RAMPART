# Vulnerability: Saia PCD Web-Server Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`saia-web-server-info.yaml`)

## Description
Saia PCD Web-Server configuration page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/loadtextfile.htm#programinfo
```

