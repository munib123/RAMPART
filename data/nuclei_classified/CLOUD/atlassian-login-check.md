# Vulnerability: Atlassian Login Check
**Classification:** CLOUD
**Source:** Nuclei Template (`atlassian-login-check.yaml`)

## Description
Checks for a valid atlassian account.

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://auth.atlassian.com/co/authenticate HTTP/1.1
Host: auth.atlassian.com
Content-Type: application/json
Origin: https://id.atlassian.com
Referer: https://id.atlassian.com/

{"username":"{{username}}","password":"{{password}}","state":{"csrfToken":"{{rand_text_alpha(10, "")}}"}}
```

