# Vulnerability: Jira Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jira-detect.yaml`)

## Description
Jira login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/secure/Dashboard.jspa
GET {{BaseURL}}/jira/secure/Dashboard.jspa
GET {{BaseURL}}/login.jsp
```

