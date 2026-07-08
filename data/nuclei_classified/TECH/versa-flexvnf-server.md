# Vulnerability: Versa FlexVNF Server
**Classification:** TECH
**Source:** Nuclei Template (`versa-flexvnf-server.yaml`)

## Description
Versa FlexVNF Server Detection (magic request params exposes Server signature/version)

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/&?=?
```

