# Vulnerability: ServiceStack Request Logs - Unauthenticated Access
**Classification:** CWE-200
**Source:** Nuclei Template (`servicestack-requestlogs.yaml`)

## Description
Detected ServiceStack Request Logs endpoint was accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/requestlogs
GET {{BaseURL}}/api/requestlogs
GET {{BaseURL}}/json/reply/RequestLogs
```

