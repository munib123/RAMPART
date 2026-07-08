# Vulnerability: NETGEAR Routers - Serial Number Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`netgear-router-exposure.yaml`)

## Description
Multiple NETGEAR router models disclose their serial number which can be used to obtain the admin password if password recovery is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/rootDesc.xml
```

