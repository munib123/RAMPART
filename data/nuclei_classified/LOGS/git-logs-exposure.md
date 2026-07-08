# Vulnerability: Git Logs Disclosure
**Classification:** LOGS
**Source:** Nuclei Template (`git-logs-exposure.yaml`)

## Description
Searches Git Logs files and passed URLs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.git/logs/HEAD
```

