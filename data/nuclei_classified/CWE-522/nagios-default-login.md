# Vulnerability: Nagios Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`nagios-default-login.yaml`)

## Description
Nagios default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /nagios/side.php HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

