# Vulnerability: Naija planet User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`naija-planet.yaml`)

## Description
Naija planet user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://naijaplanet.com/{{user}}
```

