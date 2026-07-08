# Vulnerability: Freesound User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`freesound.yaml`)

## Description
Freesound user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://freesound.org/people/{{user}}/
```

