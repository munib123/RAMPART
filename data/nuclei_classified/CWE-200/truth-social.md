# Vulnerability: Truth Social User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`truth-social.yaml`)

## Description
Truth Social user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://truthsocial.com/api/v1/accounts/lookup?acct={{user}}
```

