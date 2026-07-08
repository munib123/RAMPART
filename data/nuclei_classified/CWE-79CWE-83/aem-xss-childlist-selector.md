# Vulnerability: Adobe Experience Manager - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`aem-xss-childlist-selector.yaml`)

## Description
Adobe Experience Manager contains a cross-site scripting vulnerability via requests using the selector childlist when the dispatcher does not respect the content-type responded by AEM and flips from application/json to text/html. As a consequence, the reflected suffix is executed and interpreted in the browser.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/etc/designs/xh1x.childrenlist.json//<svg onload=alert(document.domain)>.html
```

