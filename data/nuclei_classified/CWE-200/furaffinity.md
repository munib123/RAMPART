# Vulnerability: FurAffinity User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`furaffinity.yaml`)

## Description
FurAffinity user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.furaffinity.net/user/{{user}}
```

