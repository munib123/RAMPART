# Vulnerability: Cisco Finesse Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-finesse-login.yaml`)

## Description
Cisco Finesse login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/desktop/container/landing.jsp?locale=en_US
```

