# Vulnerability: Diigo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`diigo.yaml`)

## Description
Diigo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.diigo.com/interact_api/load_profile_info?name={{user}}
```

