# Vulnerability: MongoDB Ops Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mongodb-ops-manager.yaml`)

## Description
MongoDB Ops Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/account/login
```

