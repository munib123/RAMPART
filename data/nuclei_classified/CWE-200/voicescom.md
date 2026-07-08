# Vulnerability: Voices.com User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`voicescom.yaml`)

## Description
Voices.com user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.voices.com/profile/{{user}}/
```

