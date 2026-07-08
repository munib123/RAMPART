# Vulnerability: SteVe Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`steve-default-login.yaml`)

## Description
SteVe login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /steve/manager/signin HTTP/1.1
Host: {{Hostname}}

POST /steve/manager/signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&_csrf={{csrf}}
```

