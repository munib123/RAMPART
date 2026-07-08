# Vulnerability: Netdisco Admin - Default Login
**Classification:** NETDISCO
**Source:** Nuclei Template (`netdisco-default-login.yaml`)

## Description
Detects use of hard-coded credentials in Netdisco.

## Secure Mitigation
Update the application to remove hard-coded credentials and implement secure credential management practices.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&return_url=%2Finventory
```

