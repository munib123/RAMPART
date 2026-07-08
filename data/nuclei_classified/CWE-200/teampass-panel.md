# Vulnerability: TeamPass Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`teampass-panel.yaml`)

## Description
TeamPass panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/teampass
```

