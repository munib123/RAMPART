# Vulnerability: IBM Security Verify Access - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`ibm-security-verify-default-login.yaml`)

## Description
IBM Security Verify Access default admin credentials were discovered. An unauthenticated, remote attacker can exploit this gain privileged or administrator access to the system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /core/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

j_username={{username}}&j_password={{password}}&commit=&locale=en&_method=PUT
```

