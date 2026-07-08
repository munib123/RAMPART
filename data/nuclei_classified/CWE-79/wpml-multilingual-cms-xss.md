# Vulnerability: WordPress WPML Multilingual CMS < 4.6.1 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wpml-multilingual-cms-xss.yaml`)

## Description
The WPML Multilingual CMS plugin for WordPress is vulnerable to Reflected Cross-Site Scripting (XSS) in versions prior to 4.6.1. The plugin does not escape some URL attributes before outputting them to a page, allowing attackers to inject malicious JavaScript which may be executed in the browser of an unsuspecting user.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-login.php?wp_lang=%20=id=x+type=image%20id=xss%20onfoc<!>usin+alert(`document.domain`)%0c
```

