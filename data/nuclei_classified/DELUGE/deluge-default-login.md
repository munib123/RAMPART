# Vulnerability: Deluge - Default Login
**Classification:** DELUGE
**Source:** Nuclei Template (`deluge-default-login.yaml`)

## Description
Deluge Default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /json HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"method":"auth.login","params":["{{password}}"],"id":51}
```

