# Vulnerability: Teltonika Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`teltonika-login.yaml`)

## Description
Teltonika login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/luci
```

