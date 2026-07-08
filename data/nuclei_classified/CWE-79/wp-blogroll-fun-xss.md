# Vulnerability: WordPress Blogroll Fun-Show Last Post and Last Update Time 0.8.4 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-blogroll-fun-xss.yaml`)

## Description
WordPress Plugin Blogroll Fun-Show Last Post and Last Update Time 0.8.4 and possibly prior versions are prone to a cross-site scripting vulnerability because of a failure to properly sanitize user-supplied input. An attacker may leverage this issue to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Secure Mitigation
Update to plugin version 0.8.5 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/blogroll-fun/blogroll.php?k=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

