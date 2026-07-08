# Vulnerability: Pornhub Porn Stars User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pornhub-porn-stars.yaml`)

## Description
Pornhub Porn Stars user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.pornhub.com/pornstar/{{user}}
```

