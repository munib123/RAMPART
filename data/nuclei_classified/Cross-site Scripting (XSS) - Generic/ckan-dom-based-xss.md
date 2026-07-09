# Nuclei Template: CKAN - DOM Cross-Site Scripting
**Template ID:** ckan-dom-based-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`ckan-dom-based-xss.yaml`)

## Vulnerability Information & PoC

## Description
CKAN contains a cross-site scripting vulnerability in the document object model via the previous version of the jQuery Sparkle library. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?{alert(document.domain)}
```

## References
- https://github.com/ckan/ckan/blob/b9e45e2723d4abd70fa72b16ec4a0bebc795c56b/ckan/public/base/javascript/view-filters.js#L27
- https://security.snyk.io/vuln/SNYK-PYTHON-CKAN-42010
