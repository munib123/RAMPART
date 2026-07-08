# Vulnerability: Linux.org.ru User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`linuxorgru.yaml`)

## Description
Linux.org.ru user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.linux.org.ru/people/{{user}}/profile
```

