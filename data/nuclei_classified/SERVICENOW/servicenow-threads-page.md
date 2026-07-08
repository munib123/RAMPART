# Vulnerability: ServiceNow Threads Page - Detection
**Classification:** SERVICENOW
**Source:** Nuclei Template (`servicenow-threads-page.yaml`)

## Description
Detects exposed ServiceNow thread information pages (threads.do) that reveal cluster and system details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/threads.do
```

