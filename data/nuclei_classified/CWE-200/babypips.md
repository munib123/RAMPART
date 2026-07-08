# Vulnerability: BabyPips User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`babypips.yaml`)

## Description
BabyPips user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forums.babypips.com/u/{{user}}.json
```

