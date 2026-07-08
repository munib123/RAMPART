# Vulnerability: Oqtane CMS Database - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`oqtane-db-detect.yaml`)

## Description
Detect which database distribution the target oqtane cms use.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/database
```

