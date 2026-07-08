# Vulnerability: Hewlett Packard Enterprise System Management Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hpe-system-management-login.yaml`)

## Description
Hewlett Packard Enterprise System Management login page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cpqlogin.htm
```

