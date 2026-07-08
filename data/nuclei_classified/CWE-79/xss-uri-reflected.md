# Vulnerability: Reflected XSS
**Classification:** CWE-79
**Source:** Nuclei Template (`xss-uri-reflected.yaml`)

## Description
Reflected cross-site scripting vulnerability was discovered via generic testing. Manual testing is needed to verify exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/a%22%3E%3Cinjectable%3E
GET {{BaseURL}}/a%27%3E%3Cinjectable%3E
```

