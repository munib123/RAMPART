# Vulnerability: Network Technologies Inc ENVIROMUX - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`enviromuux-default-login.yaml`)

## Description
The ENVIROMUX environment monitoring system from Network Technologies Inc was found to be using its default login credentials. This default configuration could have allowed unauthorized users to gain access to the web management interface without authentication, potentially leading to information disclosure or unauthorized control over environmental monitoring systems.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /goform/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

