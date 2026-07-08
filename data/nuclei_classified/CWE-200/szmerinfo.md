# Vulnerability: Szmer.info User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`szmerinfo.yaml`)

## Description
Szmer.info user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://szmer.info/u/{{user}}
```

