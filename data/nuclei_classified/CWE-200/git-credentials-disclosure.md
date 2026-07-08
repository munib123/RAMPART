# Vulnerability: Git Credentials - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`git-credentials-disclosure.yaml`)

## Description
Git credentials were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.git-credentials
```

