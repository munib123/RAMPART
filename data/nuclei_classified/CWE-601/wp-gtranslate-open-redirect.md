# Vulnerability: GTranslate < 2.8.11 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`wp-gtranslate-open-redirect.yaml`)

## Description
The Translate WordPress with GTranslate WordPress plugin was affected by an Unauthenticated Open Redirect security vulnerability.

## Secure Mitigation
Update GTranslate plugin to the fixed version 2.8.11

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/gtranslate/url_addon/gtranslate.php?glang=en&gurl=/oast.me
```

