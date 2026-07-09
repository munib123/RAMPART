# Nuclei Template: Redmine Issues - Exposure
**Template ID:** redmine-issues-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`redmine-issues-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Redmine instance exposed issues via the REST API without authentication. This could have leaked sensitive project information, issue details, and user data.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/issues.json
GET {{BaseURL}}/issues.json?limit=25
```

## References
- https://www.redmine.org/projects/redmine/wiki/rest_api
