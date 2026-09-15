# Nuclei Template: SquirrelMail Virtual Keyboard <=0.9.1 - Cross-Site Scripting
**Template ID:** squirrelmail-vkeyboard-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`squirrelmail-vkeyboard-xss.yaml`)

## Vulnerability Information & PoC

## Description
SquirrelMail Virtual Keyboard plugin 0.9.1 and prior contains a cross-site scripting vulnerability via the vkeyboard.php parameter. It fails to properly sanitize user-supplied input, which allows an attacker to execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/plugins/vkeyboard/vkeyboard.php?passformname={{url_encode(payload)}}
```

## References
- https://www.exploit-db.com/exploits/34814
