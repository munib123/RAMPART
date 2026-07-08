# Vulnerability: Leantime - Detect
**Classification:** TECH
**Source:** Nuclei Template (`leantime-detect.yaml`)

## Description
Detects a Leantime server, a project management system for non-project managers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

