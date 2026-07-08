# Vulnerability: Adultism User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`adultism.yaml`)

## Description
Adultism user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.adultism.com/profile/{{user}}
```

