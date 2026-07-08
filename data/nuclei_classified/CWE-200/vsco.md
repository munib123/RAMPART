# Vulnerability: Vsco User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vsco.yaml`)

## Description
Vsco user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://vsco.co/{{user}}/gallery
```

