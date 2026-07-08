# Vulnerability: Grafana Public Signup
**Classification:** GRAFANA
**Source:** Nuclei Template (`grafana-public-signup.yaml`)

## Description
Public Signup is enabled on Grafana.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/user/signup/step2 HTTP/1.1
Host: {{Hostname}}
content-type: application/json
Origin: {{BaseURL}}
Referer: {{BaseURL}}

{"username":"{{randstr}}","password":"{{randstr_1}}"}
```

