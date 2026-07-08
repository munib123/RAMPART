# Vulnerability: LuCi Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`luci-login-detection.yaml`)

## Description
LuCi login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/luci
```

