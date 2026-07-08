# Vulnerability: Shibboleth SSO Detect
**Classification:** SHIBBOLETH
**Source:** Nuclei Template (`shibboleth-detect.yaml`)

## Description
A Shibboleth SSO panel was detected

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/shibboleth-idp
```

