# Vulnerability: SquirrelMail Virtual Keyboard <=0.9.1 - Cross-Site Scripting
**Classification:** CWE-80,CWE-83
**Source:** Nuclei Template (`squirrelmail-vkeyboard-xss.yaml`)

## Description
SquirrelMail Virtual Keyboard plugin 0.9.1 and prior contains a cross-site scripting vulnerability via the vkeyboard.php parameter. It fails to properly sanitize user-supplied input, which allows an attacker to execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plugins/vkeyboard/vkeyboard.php?passformname={{url_encode(payload)}}
```

