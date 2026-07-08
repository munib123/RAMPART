# Vulnerability: Fireware XTM Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fireware-xtm-user-authentication.yaml`)

## Description
Fireware XTM login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sslvpn_logon.shtml
```

