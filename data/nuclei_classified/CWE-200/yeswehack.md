# Vulnerability: Yeswehack User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`yeswehack.yaml`)

## Description
Yeswehack user name information check was conducted. Detection will work if the profile is set to be public.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.yeswehack.com/hacktivity/{{user}}
```

