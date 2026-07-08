# Vulnerability: Okidoki User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`okidoki.yaml`)

## Description
Okidoki user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://m.okidoki.ee/ru/users/{{user}}/
```

