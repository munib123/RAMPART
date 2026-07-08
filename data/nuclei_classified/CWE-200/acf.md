# Vulnerability: ACF User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`acf.yaml`)

## Description
ACF user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://support.advancedcustomfields.com/forums/users/{{user}}
```

