# Vulnerability: Mediakits User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mediakits.yaml`)

## Description
Mediakits user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://restapi.mediakits.com/mediakits/{{user}}
```

