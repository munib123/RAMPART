# Vulnerability: Apache Tomcat - Default Login Discovery
**Classification:** CWE-200
**Source:** Nuclei Template (`tomcat-examples-login.yaml`)

## Description
Apache Tomcat 10.1.0-M1 to 10.1.0-M16, 10.0.0-M1 to 10.0.22, 9.0.30 to 9.0.64 and 8.5.50 to 8.5.81  default login credentials were successful.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /examples/jsp/security/protected/index.jsp HTTP/1.1
Host: {{Hostname}}

POST /examples/jsp/security/protected/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

j_username={{username}}&j_password={{password}}
```

