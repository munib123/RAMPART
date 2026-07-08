# Vulnerability: Nagios Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nagios-panel.yaml`)

## Description
Nagios login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nagios
GET {{BaseURL}}/nagios3
```

