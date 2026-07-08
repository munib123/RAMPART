# Vulnerability: Zillow User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zillow.yaml`)

## Description
Zillow user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.zillow.com/profile/{{user}}/
```

