# Vulnerability: Github Enterprise Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`github-enterprise-detect.yaml`)

## Description
Github Enterprise login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

