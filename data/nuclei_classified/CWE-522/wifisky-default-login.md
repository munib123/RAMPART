# Vulnerability: Wifisky Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`wifisky-default-login.yaml`)

## Description
Wifisky default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.php?action=login&type=admin HTTP/1.1
Host: {{Hostname}}
Accept: */*
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Connection: close

username={{username}}&password={{password}}
```

