# Vulnerability: ArtBreeder User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`artbreeder.yaml`)

## Description
ArtBreeder user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.artbreeder.com/{{user}}
```

