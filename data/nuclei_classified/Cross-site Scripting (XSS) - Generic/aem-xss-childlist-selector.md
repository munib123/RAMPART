# Nuclei Template: Adobe Experience Manager - Cross-Site Scripting
**Template ID:** aem-xss-childlist-selector
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`aem-xss-childlist-selector.yaml`)

## Vulnerability Information & PoC

## Description
Adobe Experience Manager contains a cross-site scripting vulnerability via requests using the selector childlist when the dispatcher does not respect the content-type responded by AEM and flips from application/json to text/html. As a consequence, the reflected suffix is executed and interpreted in the browser.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/etc/designs/xh1x.childrenlist.json//<svg onload=alert(document.domain)>.html
```

## References
- https://github.com/thomashartm/burp-aem-scanner/blob/master/src/main/java/burp/actions/xss/FlippingTypeWithChildrenlistSelector.java
- https://cystack.net/en/plugins/cystack.remote.aem_childlist_selector_xss
