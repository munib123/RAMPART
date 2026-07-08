# Vulnerability: Bittube User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bittube.yaml`)

## Description
Bittube user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bittube.video/c/{{user}}/videos
```

