# Vulnerability: Kerio Connect Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kerio-connect-client.yaml`)

## Description
Kerio Connect login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webmail/login/
```

