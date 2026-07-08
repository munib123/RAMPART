# Vulnerability: Gpodder.net User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gpoddernet.yaml`)

## Description
Gpodder.net user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://gpodder.net/user/{{user}}/
```

