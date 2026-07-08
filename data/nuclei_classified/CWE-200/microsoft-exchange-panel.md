# Vulnerability: Microsoft Exchange Admin Center Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`microsoft-exchange-panel.yaml`)

## Description
Microsoft Exchange Admin Center login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/owa/auth/logon.aspx?replaceCurrent=1&url={{BaseURL}}/ecp
```

