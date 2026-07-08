# Vulnerability: Bagisto 2.1.2 Client-Side Template Injection
**Classification:** CWE-94
**Source:** Nuclei Template (`bagisto-csti.yaml`)

## Description
Bagisto is vulnerable to Client-Side Template Injection (CSTI), which allows an attacker to execute arbitrary code on the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bagisto-common/search?query={{2288*'9876'}}
```

