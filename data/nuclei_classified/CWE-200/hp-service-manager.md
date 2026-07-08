# Vulnerability: HP Service Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hp-service-manager.yaml`)

## Description
HP Service Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sm935/index.do
GET {{BaseURL}}/sm/ess.do
```

