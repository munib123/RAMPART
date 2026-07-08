# Vulnerability: Moneysavingexpert User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`moneysavingexpert.yaml`)

## Description
Moneysavingexpert user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forums.moneysavingexpert.com/profile/{{user}}
```

