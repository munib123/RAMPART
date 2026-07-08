# Vulnerability: Curiouscat User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`curiouscat.yaml`)

## Description
Curiouscat user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://curiouscat.live/api/v2.1/profile?username={{user}}
```

