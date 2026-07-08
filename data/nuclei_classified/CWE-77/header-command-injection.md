# Vulnerability: Header - Remote Command Injection
**Classification:** CWE-77
**Source:** Nuclei Template (`header-command-injection.yaml`)

## Description
Headers were tested for remote command injection vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /?{{header}} HTTP/1.1
Host: {{Hostname}}
{{header}}: {{payload}}
```

