# Vulnerability: ArtStation User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`artstation.yaml`)

## Description
ArtStation user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.artstation.com/{{user}}
```

