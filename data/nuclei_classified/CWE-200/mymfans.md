# Vulnerability: Mym.fans User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mymfans.yaml`)

## Description
Mym.fans user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mym.fans/{{user}}
```

