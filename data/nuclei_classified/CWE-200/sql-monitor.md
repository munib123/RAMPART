# Vulnerability: SQL Monitor - Discovery
**Classification:** CWE-200
**Source:** Nuclei Template (`sql-monitor.yaml`)

## Description
SQL Monitor was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Account/LogIn?returnUrl=%2F&hasAttemptedCookie=True
```

