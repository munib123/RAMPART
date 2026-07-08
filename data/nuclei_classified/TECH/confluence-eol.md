# Vulnerability: Atlassian Confluence End-of-Life - Detect
**Classification:** TECH
**Source:** Nuclei Template (`confluence-eol.yaml`)

## Description
Detected Atlassian Confluence instances versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.action
GET {{BaseURL}}
```

