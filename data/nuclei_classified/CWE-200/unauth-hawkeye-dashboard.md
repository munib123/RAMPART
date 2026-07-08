# Vulnerability: Unauth Hawkeye Dashboard - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-hawkeye-dashboard.yaml`)

## Description
Hawkeye Dashboard was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard
```

