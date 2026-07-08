# Vulnerability: security.txt File
**Classification:** MISCELLANEOUS
**Source:** Nuclei Template (`security-txt.yaml`)

## Description
File similar to robots.txt but intended to be read by humans wishing to contact a website’s owner about security issues. Often defines a security policy and contact details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{RootURL}}/.well-known/security.txt
GET {{RootURL}}/security.txt
```

