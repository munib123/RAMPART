# Vulnerability: TAPiTAG User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tapitag.yaml`)

## Description
TAPiTAG user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://account.tapitag.co/tapitag/api/v1/{{user}}
```

