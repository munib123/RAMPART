# Vulnerability: Mitel Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mitel-panel-detect.yaml`)

## Description
Mitel login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/server-common/cgi-bin/login
```

