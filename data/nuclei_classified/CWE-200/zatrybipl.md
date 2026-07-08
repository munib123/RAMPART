# Vulnerability: Zatrybi.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zatrybipl.yaml`)

## Description
Zatrybi.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://zatrybi.pl/user/{{user}}
```

