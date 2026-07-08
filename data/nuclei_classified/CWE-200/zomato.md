# Vulnerability: Zomato User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zomato.yaml`)

## Description
Zomato user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.zomato.com/{{user}}/foodjourney
```

