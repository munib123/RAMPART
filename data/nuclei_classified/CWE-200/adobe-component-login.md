# Vulnerability: Adobe ColdFusion Component Browser Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`adobe-component-login.yaml`)

## Description
An Adobe ColdFusion Component Browser login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CFIDE/componentutils/login.cfm
GET {{BaseURL}}/cfide/componentutils/login.cfm
```

