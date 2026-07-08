# Vulnerability: Blue Yonder Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`blue-yonder-panel.yaml`)

## Description
Blue Yonder login panel was discovered

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/base/home
```

