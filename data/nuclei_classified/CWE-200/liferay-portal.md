# Vulnerability: Liferay Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`liferay-portal.yaml`)

## Description
Liferay login panel was detected,

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/jsonws
GET {{BaseURL}}/api/jsonws/invoke
```

