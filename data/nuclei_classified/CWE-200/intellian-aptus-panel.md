# Vulnerability: Intellian Aptus Web Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`intellian-aptus-panel.yaml`)

## Description
Intelllian Aptus Web login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/getagent.cgi?type=s&xxxx
```

