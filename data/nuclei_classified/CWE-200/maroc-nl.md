# Vulnerability: Maroc nl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`maroc-nl.yaml`)

## Description
Maroc nl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.maroc.nl/forums/members/{{user}}.html
```

