# Vulnerability: Oracle Enterprise Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`oracle-enterprise-manager-login.yaml`)

## Description
Oracle Enterprise Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/em/console/logon/logon
```

