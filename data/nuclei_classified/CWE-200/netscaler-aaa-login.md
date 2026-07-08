# Vulnerability: NetScaler AAA Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netscaler-aaa-login.yaml`)

## Description
NetScaler AAA login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/logon/LogonPoint/tmindex.html
```

