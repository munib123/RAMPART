# Vulnerability: Netflix Conductor Version Detection
**Classification:** MISCELLANEOUS
**Source:** Nuclei Template (`netflix-conductor-version.yaml`)

## Description
Obtain netflix conductor version information

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/admin/config
GET {{BaseURL}}/api/sys
```

