# Vulnerability: Uefconnect User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`uefconnect.yaml`)

## Description
Uefconnect user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://uefconnect.uef.fi/en/person/{{user}}/
```

