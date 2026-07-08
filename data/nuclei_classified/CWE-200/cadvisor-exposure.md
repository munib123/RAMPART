# Vulnerability: cAdvisor - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cadvisor-exposure.yaml`)

## Description
cAdvisor page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/containers/
```

