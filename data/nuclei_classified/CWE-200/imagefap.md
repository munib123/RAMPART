# Vulnerability: Imagefap User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`imagefap.yaml`)

## Description
Imagefap user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.imagefap.com/profile/{{user}}
```

