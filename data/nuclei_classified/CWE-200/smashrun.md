# Vulnerability: SmashRun User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`smashrun.yaml`)

## Description
SmashRun user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://smashrun.com/{{user}}/
```

