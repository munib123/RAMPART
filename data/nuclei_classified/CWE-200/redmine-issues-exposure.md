# Vulnerability: Redmine Issues - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`redmine-issues-exposure.yaml`)

## Description
Redmine instance exposed issues via the REST API without authentication. This could have leaked sensitive project information, issue details, and user data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/issues.json
GET {{BaseURL}}/issues.json?limit=25
```

