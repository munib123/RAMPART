# Vulnerability: Atlassian Crowd Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`atlassian-crowd-panel.yaml`)

## Description
An Atlassian Crowd login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/crowd/console/login.action
```

