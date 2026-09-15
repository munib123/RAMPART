# Nuclei Template: Header - Remote Command Injection
**Template ID:** header-command-injection
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`header-command-injection.yaml`)

## Vulnerability Information & PoC

## Description
Headers were tested for remote command injection vulnerabilities.

## Steps to reproduce / Exploit Payload
```http
GET /?{{header}} HTTP/1.1
Host: {{Hostname}}
{{header}}: {{payload}}
```

