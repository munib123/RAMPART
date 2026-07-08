# Vulnerability: FastCGI Test Page
**Classification:** TECH
**Source:** Nuclei Template (`fastcgi-test-page.yaml`)

## Description
FastCGI test page was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/test/fcgi/test.html
```

