# Vulnerability: Acunetix Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`acunetix-panel.yaml`)

## Description
An Acunetix login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login
```

