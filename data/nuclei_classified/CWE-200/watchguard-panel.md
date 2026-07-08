# Vulnerability: Watchguard Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`watchguard-panel.yaml`)

## Description
Watchguard login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sslvpn_logon.shtml
```

