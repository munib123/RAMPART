# Vulnerability: Disqus User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`disqus.yaml`)

## Description
Disqus user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://disqus.com/by/{{user}}/
```

