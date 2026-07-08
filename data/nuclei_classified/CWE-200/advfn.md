# Vulnerability: ADVFN User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`advfn.yaml`)

## Description
ADVFN user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://uk.advfn.com/forum/profile/{{user}}
```

