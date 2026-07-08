# Vulnerability: Inaturalist User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`inaturalist.yaml`)

## Description
Inaturalist user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://inaturalist.nz/people/{{user}}
```

