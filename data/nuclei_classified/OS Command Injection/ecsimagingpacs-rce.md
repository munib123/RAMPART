# Nuclei Template: ECSIMAGING PACS <= 6.21.5 - Command Execution and Local File Inclusion
**Template ID:** ecsimagingpacs-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`ecsimagingpacs-rce.yaml`)

## Vulnerability Information & PoC

## Description
ECSIMAGING PACS Application 6.21.5 and below suffer from a command injection vulnerability and a local file include vulnerability. The 'file' parameter on the page /showfile.php can be exploited to perform command execution or local file inclusion. Often on ECSIMAGING PACS, the www-data user has sudo NOPASSWD access.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/showfile.php?file=/etc/passwd
```

## References
- https://www.exploit-db.com/exploits/49388
