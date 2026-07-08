# Vulnerability: Soc.citizen4.eu User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`soccitizen4eu.yaml`)

## Description
Soc.citizen4.eu user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://soc.citizen4.eu/profile/{{user}}/profile
```

