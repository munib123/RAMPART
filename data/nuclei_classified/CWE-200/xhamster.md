# Vulnerability: XHamster User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xhamster.yaml`)

## Description
XHamster user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://xhamster.com/users/{{user}}
```

