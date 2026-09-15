# Nuclei Template: ServiceStack Request Logs - Unauthenticated Access
**Template ID:** servicestack-requestlogs
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`servicestack-requestlogs.yaml`)

## Vulnerability Information & PoC

## Description
Detected ServiceStack Request Logs endpoint was accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/requestlogs
GET {{BaseURL}}/api/requestlogs
GET {{BaseURL}}/json/reply/RequestLogs
```

## References
- https://docs.servicestack.net/request-logger
- https://docs.servicestack.net/admin-ui-profiling
