# Vulnerability: SeedDMS Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`seeddms-default-login.yaml`)

## Description
SeedDMS default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /op/op.Login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

login={{username}}&pwd={{password}}&lang=
```

