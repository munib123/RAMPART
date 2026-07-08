# Vulnerability: OA E-Office UserSelect Unauthorized Access
**Classification:** WEAVER
**Source:** Nuclei Template (`weaver-userselect-unauth.yaml`)

## Description
OA E-Office UserSelect interface has an unauthorized access vulnerability, through which attackers can obtain sensitive information

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/UserSelect/
```

