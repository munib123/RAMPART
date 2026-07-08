# Vulnerability: CKAN - DOM Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`ckan-dom-based-xss.yaml`)

## Description
CKAN contains a cross-site scripting vulnerability in the document object model via the previous version of the jQuery Sparkle library. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?{alert(document.domain)}
```

