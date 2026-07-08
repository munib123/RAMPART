# Vulnerability: BiggerPockets User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`biggerpockets.yaml`)

## Description
BiggerPockets user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.biggerpockets.com/users/{{user}}
```

