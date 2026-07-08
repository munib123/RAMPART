# Vulnerability: Jira Rest API Server Information
**Classification:** CWE-200
**Source:** Nuclei Template (`jira-serverinfo.yaml`)

## Description
Detected Jira REST API serverInfo endpoint is accessible without authentication, exposing sensitive server information including version, build number, server title, base URL, and server time.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/rest/api/latest/serverInfo
GET {{BaseURL}}/rest/api/2/serverInfo
```

