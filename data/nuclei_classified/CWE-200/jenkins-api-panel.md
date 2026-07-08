# Vulnerability: Jenkins API Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jenkins-api-panel.yaml`)

## Description
Jenkins API panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/xml
```

