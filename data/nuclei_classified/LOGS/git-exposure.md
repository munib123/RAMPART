# Vulnerability: Git Metadata Directory Exposure
**Classification:** LOGS
**Source:** Nuclei Template (`git-exposure.yaml`)

## Description
Git Metadata Directory exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.git/
```

