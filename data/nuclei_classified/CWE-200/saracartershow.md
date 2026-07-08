# Vulnerability: SaraCarterShow User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`saracartershow.yaml`)

## Description
SaraCarterShow user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://saraacarter.com/author/{{user}}/
```

