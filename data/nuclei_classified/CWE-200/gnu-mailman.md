# Vulnerability: GNU Mailman Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gnu-mailman.yaml`)

## Description
GNU Mailman panel was detected. Panel exposes all public mailing lists on server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mailman/listinfo
GET {{BaseURL}}/listinfo
```

