# Vulnerability: Uninitialized GitLab instances
**Classification:** GITLAB
**Source:** Nuclei Template (`gitlab-uninitialized-password.yaml`)

## Description
Prior to version 14, GitLab installations required a root password to be
set via the web UI. If the administrator skipped this step, any visitor
could set a password and control the instance.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/users/sign_in
```

