# Vulnerability: Weblate User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`weblate.yaml`)

## Description
Weblate user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hosted.weblate.org/user/{{user}}/
```

