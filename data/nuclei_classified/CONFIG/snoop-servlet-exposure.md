# Vulnerability: Snoop Servlet - Information Disclosure
**Classification:** CONFIG
**Source:** Nuclei Template (`snoop-servlet-exposure.yaml`)

## Description
The Snoop Servlet returns information about the HTTP request itself and sometimes. It could help an attacker to prepare more advanced attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/snoop
```

