# Vulnerability: Gitea Public Registration Enabled
**Classification:** MISCONFIG
**Source:** Nuclei Template (`gitea-public-signup.yaml`)

## Description
A misconfiguration in Gitea allows arbitrary users to sign up and read code hosted on the service.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user/sign_up
```

