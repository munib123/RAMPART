# Vulnerability: SmugMug User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`smugmug.yaml`)

## Description
SmugMug user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{valid_username}}.smugmug.com
```

