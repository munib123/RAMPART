# Vulnerability: Apache Tomcat Manager Default Login
**Classification:** TOMCAT
**Source:** Nuclei Template (`tomcat-default-login.yaml`)

## Description
Apache Tomcat Manager default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /manager/html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

